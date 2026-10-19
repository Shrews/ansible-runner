# pylint: disable=R0914

import io
import time
import tempfile
import zipfile
import os
import json
import sys
import stat
from pathlib import Path

from .base64io import Base64IO


def stream_dir(source_directory: str, stream: io.FileIO) -> None:
    with tempfile.NamedTemporaryFile() as tmp:
        with zipfile.ZipFile(
            tmp.name, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True, strict_timestamps=False
        ) as archive:
            if source_directory:
                for dirpath, dirs, files in os.walk(source_directory):
                    relpath = os.path.relpath(dirpath, source_directory)
                    if relpath == ".":
                        relpath = ""
                    for fname in files + dirs:
                        full_path = os.path.join(dirpath, fname)
                        # Magic to preserve symlinks
                        if os.path.islink(full_path):
                            archive_relative_path = os.path.relpath(dirpath, source_directory)
                            file_relative_path = os.path.join(archive_relative_path, fname)
                            zip_info = zipfile.ZipInfo(file_relative_path)
                            zip_info.create_system = 3
                            permissions = 0o777
                            permissions |= 0xA000
                            zip_info.external_attr = permissions << 16
                            archive.writestr(zip_info, os.readlink(full_path))
                        elif stat.S_ISFIFO(os.stat(full_path).st_mode):
                            # skip any pipes, as python hangs when attempting
                            # to open them.
                            # i.e. ssh_key_data that was never cleaned up
                            continue
                        else:
                            archive.write(
                                os.path.join(dirpath, fname), arcname=os.path.join(relpath, fname)
                            )
            archive.close()

        zip_size = Path(tmp.name).stat().st_size

        with open(tmp.name, "rb") as source:
            if stream.name == "<stdout>":
                target = sys.stdout.buffer
            else:
                target = stream
            target.write(json.dumps({"zipfile": zip_size}).encode("utf-8") + b"\n")
            target.flush()
            with Base64IO(target) as encoded_target:
                for line in source:
                    encoded_target.write(line)


def _is_within_directory(parent: str, child: str) -> bool:
    """Return True iff child resolves to a path inside parent (or equal to it).
    Uses ``os.path.realpath`` on both sides so the comparison reflects what
    ``open``/``os.symlink`` would actually do on disk (symlinks resolved,
    ``..`` normalized).
    """
    parent_abs = os.path.realpath(parent)
    child_abs = os.path.realpath(child)
    if child_abs == parent_abs:
        return True
    return child_abs.startswith(parent_abs + os.sep)


def unstream_dir(stream: io.FileIO, length: int, target_directory: str) -> None:
    # NOTE: caller needs to process exceptions
    with tempfile.NamedTemporaryFile() as tmp:
        with open(tmp.name, "wb") as target:
            with Base64IO(stream) as source:
                remaining = length
                chunk_size = 1024 * 1000  # 1 MB
                while remaining != 0:
                    chunk_size = min(chunk_size, remaining)

                    data = source.read(chunk_size)
                    target.write(data)

                    remaining -= chunk_size

        # Snapshot the realpath of the destination once. We use it to bound
        # every member, link target and ancestor we touch below.
        target_root = os.path.realpath(target_directory)

        with zipfile.ZipFile(tmp.name, "r") as archive:
            # Fancy extraction in order to preserve permissions
            # AWX relies on the execution bit, in particular, for inventory
            # https://www.burgundywall.com/post/preserving-file-perms-with-python-zipfile-module
            for info in archive.infolist():
                # Reject member names whose normalized path would escape the
                # destination (absolute paths or paths starting with "..").
                # zipfile.ZipFile.extract already rejects these, but we want
                # the gate in front of the symlink-ancestor check below so the
                # subsequent logic is unconditionally safe.
                member_norm = os.path.normpath(info.filename)
                if (os.path.isabs(member_norm)
                        or member_norm == ".."
                        or member_norm.startswith(".." + os.sep)):
                    raise zipfile.BadZipFile(
                        "Refusing to extract member that escapes target directory: "
                        "%r" % info.filename
                    )

                out_path = os.path.join(target_directory, info.filename)

                # Walk every ancestor of out_path up to the target directory.
                # If any ancestor is a symbolic link, an earlier entry has
                # planted a link we would otherwise traverse during
                # archive.extract(); refuse rather than write through it.
                #
                # ancestor is derived from the raw target_directory (via
                # out_path), so bound the walk with the normalized raw path
                # rather than target_root (its realpath): when target_directory
                # is itself a symlink the two can differ in both length and
                # string, which would break the loop's stop condition.
                target_norm = os.path.normpath(target_directory)
                ancestor = os.path.dirname(os.path.normpath(out_path))
                while (len(ancestor) > len(target_norm)
                        and ancestor != target_norm):
                    if os.path.islink(ancestor):
                        raise zipfile.BadZipFile(
                            "Refusing to write through symlinked ancestor: %r"
                            % ancestor
                        )
                    ancestor = os.path.dirname(ancestor)

                perms = info.external_attr >> 16
                mode = stat.filemode(perms)

                is_symlink = mode[:1] == 'l'
                if os.path.exists(out_path):
                    if is_symlink:
                        os.remove(out_path)
                    elif stat.S_ISFIFO(os.stat(out_path).st_mode):
                        # remove any pipes, as python hangs when attempting
                        # to open them.
                        # i.e. ssh_key_data that was never cleaned up
                        os.remove(out_path)
                        continue
                    elif os.path.isdir(out_path):
                        # Special case, the important dirs were pre-created so don't try to chmod them
                        continue

                archive.extract(info.filename, path=target_directory)

                # Fancy logic to preserve modification times
                # AWX uses modification times to determine if new facts were written for a host
                # https://stackoverflow.com/questions/9813243/extract-files-from-zip-file-and-retain-mod-date
                date_time = time.mktime(info.date_time + (0, 0, -1))
                os.utime(out_path, times=(date_time, date_time))

                if is_symlink:
                    with open(out_path) as fd:
                        link = fd.read()
                    # Resolve the link target against the link's own parent
                    # (matches the semantics os.symlink would use at lookup
                    # time) and require it to land inside target_root.
                    link_parent = os.path.dirname(out_path)
                    resolved = os.path.realpath(
                        os.path.join(link_parent, link)
                    )
                    if not _is_within_directory(target_root, resolved):
                        os.remove(out_path)
                        raise zipfile.BadZipFile(
                            "Refusing to create symbolic link that escapes "
                            "target directory: %r -> %r" % (out_path, link)
                        )
                    os.remove(out_path)
                    os.symlink(link, out_path)
                else:
                    os.chmod(out_path, perms)
