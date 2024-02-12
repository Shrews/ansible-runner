from __future__ import annotations

import json
import logging
import os
import stat
import tempfile

from abc import ABC
from base64 import b64encode

from ansible_runner.config._base import BaseConfig, BaseExecutionMode
from ansible_runner.defaults import registry_auth_prefix
from ansible_runner.exceptions import ConfigurationError
from ansible_runner.utils import cli_mounts, register_for_cleanup


logger = logging.getLogger('ansible-runner')


class BaseEngine(ABC):

    def __init__(self, config: BaseConfig):
        self.config = config

    ##############################################################
    # Public methods
    ##############################################################

    def default_args(self,
                     args: list[str],
                     execution_mode: BaseExecutionMode,
                     cmdline_args: list[str],
                     ) -> list[str]:
        new_args = [self.config.process_isolation_executable]
        new_args.extend(['run', '--rm'])

        if self.config.runner_mode == 'pexpect' or getattr(self.config, 'input_fd', False):
            new_args.extend(['--tty'])

        new_args.append('--interactive')

        if self.config.container_workdir:
            workdir = self.config.container_workdir
        elif self.config.host_cwd is not None and os.path.exists(self.config.host_cwd):
            # mount current host working diretory if passed and exist
            self._ensure_path_safe_to_mount(self.config.host_cwd)
            self._update_volume_mount_paths(new_args, self.config.host_cwd)
            workdir = self.config.host_cwd
        else:
            workdir = "/runner/project"

        self.config.cwd = workdir
        new_args.extend(["--workdir", workdir])

        # For run() and run_async() API value of base execution_mode is 'BaseExecutionMode.NONE'
        # and the container volume mounts are handled separately using 'container_volume_mounts'
        # hence ignore additional mount here
        if execution_mode != BaseExecutionMode.NONE:
            if execution_mode == BaseExecutionMode.ANSIBLE_COMMANDS:
                self._handle_ansible_cmd_options_bind_mounts(new_args, cmdline_args)

            # Handle automounts for .ssh config
            self._handle_automounts(new_args)

            if 'podman' in self.config.process_isolation_executable:
                # container namespace stuff
                new_args.extend(["--group-add=root"])
                new_args.extend(["--ipc=host"])

            self._ensure_path_safe_to_mount(self.config.private_data_dir)
            # Relative paths are mounted relative to /runner/project
            for subdir in ('project', 'artifacts'):
                subdir_path = os.path.join(self.config.private_data_dir, subdir)
                if not os.path.exists(subdir_path):
                    os.mkdir(subdir_path, 0o700)
            # runtime commands need artifacts mounted to output data
            self._update_volume_mount_paths(new_args,
                                            f"{self.config.private_data_dir}/artifacts",
                                            dst_mount_path="/runner/artifacts",
                                            labels=":Z")
        else:
            subdir_path = os.path.join(self.config.private_data_dir, 'artifacts')
            if not os.path.exists(subdir_path):
                os.mkdir(subdir_path, 0o700)

        # Mount the entire private_data_dir
        # custom show paths inside private_data_dir do not make sense
        self._update_volume_mount_paths(new_args, self.config.private_data_dir, dst_mount_path="/runner", labels=":Z")

        if self.config.container_auth_data:
            # Pull in the necessary registry auth info, if there is a container cred
            self.config.registry_auth_path, registry_auth_conf_file = self._generate_container_auth_dir(self.config.container_auth_data)
            if 'podman' in self.config.process_isolation_executable:
                new_args.extend([f"--authfile={self.config.registry_auth_path}"])
            else:
                docker_idx = new_args.index(self.config.process_isolation_executable)
                new_args.insert(docker_idx + 1, f"--config={self.config.registry_auth_path}")
            if registry_auth_conf_file is not None:
                # Podman >= 3.1.0
                self.config.env['CONTAINERS_REGISTRIES_CONF'] = registry_auth_conf_file
                # Podman < 3.1.0
                self.config.env['REGISTRIES_CONFIG_PATH'] = registry_auth_conf_file

        if self.config.container_volume_mounts:
            for mapping in self.config.container_volume_mounts:
                volume_mounts = mapping.split(':', 2)
                self._ensure_path_safe_to_mount(volume_mounts[0])
                labels = None
                if len(volume_mounts) == 3:
                    labels = f":{volume_mounts[2]}"
                self._update_volume_mount_paths(new_args, volume_mounts[0], dst_mount_path=volume_mounts[1], labels=labels)

        # Reference the file with list of keys to pass into container
        # this file will be written in ansible_runner.runner
        env_file_host = os.path.join(self.config.artifact_dir, 'env.list')
        new_args.extend(['--env-file', env_file_host])

        if 'podman' in self.config.process_isolation_executable:
            # docker doesnt support this option
            new_args.extend(['--quiet'])

        if 'docker' in self.config.process_isolation_executable:
            new_args.extend([f'--user={os.getuid()}'])

        new_args.extend(['--name', self.config.container_name])

        if self.config.container_options:
            new_args.extend(self.config.container_options)

        new_args.extend([self.config.container_image])
        new_args.extend(args)
        logger.debug("container engine invocation: %s", ' '.join(new_args))
        return new_args

    ##############################################################
    # Private methods
    ##############################################################

    def _ensure_path_safe_to_mount(self, path: str) -> None:
        if os.path.isfile(path):
            path = os.path.dirname(path)
        if os.path.join(path, "") in ('/', '/home/', '/usr/'):
            raise ConfigurationError("When using containerized execution, cannot mount '/' or '/home' or '/usr'")

    def _handle_automounts(self, new_args: list[str]) -> None:
        for cli_automount in cli_mounts():
            for env in cli_automount['ENVS']:
                if env in os.environ:
                    dest_path = os.environ[env]

                    if os.path.exists(os.environ[env]):
                        if os.environ[env].startswith(os.environ['HOME']):
                            dest_path = f"/home/runner/{os.environ[env].lstrip(os.environ['HOME'])}"
                        elif os.environ[env].startswith('~'):
                            dest_path = f"/home/runner/{os.environ[env].lstrip('~/')}"
                        else:
                            dest_path = os.environ[env]

                        self._update_volume_mount_paths(new_args, os.environ[env], dst_mount_path=dest_path)

                    new_args.extend(["-e", f"{env}={dest_path}"])

            for paths in cli_automount['PATHS']:
                if os.path.exists(paths['src']):
                    self._update_volume_mount_paths(new_args, paths['src'], dst_mount_path=paths['dest'])

    def _update_volume_mount_paths(self,
                                   args_list: list[str],
                                   src_mount_path: str | None,
                                   dst_mount_path: str | None = None,
                                   labels: str | None = None
                                   ) -> None:

        if src_mount_path is None or not os.path.exists(src_mount_path):
            logger.debug("Source volume mount path does not exist: %s", src_mount_path)
            return

        # ensure source is abs
        src_path = os.path.abspath(os.path.expanduser(os.path.expandvars(src_mount_path)))

        # set dest src (if None) relative to workdir(not absolute) or provided
        if dst_mount_path is None:
            dst_path = src_path
        elif self.config.container_workdir and not os.path.isabs(dst_mount_path):
            dst_path = os.path.abspath(
                os.path.expanduser(
                    os.path.expandvars(os.path.join(self.config.container_workdir, dst_mount_path))
                )
            )
        else:
            dst_path = os.path.abspath(os.path.expanduser(os.path.expandvars(dst_mount_path)))

        # ensure each is a directory not file, use src for dest
        # because dest doesn't exist locally
        src_dir = src_path if os.path.isdir(src_path) else os.path.dirname(src_path)
        dst_dir = dst_path if os.path.isdir(src_path) else os.path.dirname(dst_path)

        # always ensure a trailing slash
        src_dir = os.path.join(src_dir, "")
        dst_dir = os.path.join(dst_dir, "")

        # ensure the src and dest are safe mount points
        # after stripping off the file and resolving
        self._ensure_path_safe_to_mount(src_dir)
        self._ensure_path_safe_to_mount(dst_dir)

        # format the src dest str
        volume_mount_path = f"{src_dir}:{dst_dir}"

        # add labels as needed
        if labels:
            if not labels.startswith(":"):
                volume_mount_path += ":"
            volume_mount_path += labels

        # check if mount path already added in args list
        if volume_mount_path not in args_list:
            args_list.extend(["-v", volume_mount_path])

    def _handle_ansible_cmd_options_bind_mounts(self, args_list: list[str], cmdline_args: list[str]) -> None:
        inventory_file_options = ['-i', '--inventory', '--inventory-file']
        vault_file_options = ['--vault-password-file', '--vault-pass-file']
        private_key_file_options = ['--private-key', '--key-file']

        optional_mount_args = inventory_file_options + vault_file_options + private_key_file_options

        if not cmdline_args:
            return

        if '-h' in cmdline_args or '--help' in cmdline_args:
            return

        for value in self.config.command:
            if 'ansible-playbook' in value:
                playbook_file_path = self._get_playbook_path(cmdline_args)
                if playbook_file_path:
                    self._update_volume_mount_paths(args_list, playbook_file_path)
                    break

        cmdline_args_copy = cmdline_args.copy()
        optional_arg_paths = []
        for arg in cmdline_args:

            if arg not in optional_mount_args:
                continue

            optional_arg_index = cmdline_args_copy.index(arg)
            optional_arg_paths.append(cmdline_args[optional_arg_index + 1])
            cmdline_args_copy.pop(optional_arg_index)
            try:
                optional_arg_value = cmdline_args_copy.pop(optional_arg_index)
            except IndexError:
                # invalid command, pass through for execution
                # to return valid error from ansible-core
                return

            if arg in inventory_file_options and optional_arg_value.endswith(','):
                # comma separated host list provided as value
                continue

            self._update_volume_mount_paths(args_list, optional_arg_value)

    def _generate_container_auth_dir(self, auth_data: dict[str, str]) -> tuple[str, str | None]:
        host = auth_data.get('host')
        token = f"{auth_data.get('username')}:{auth_data.get('password')}"
        encoded_container_auth_data = {'auths': {host: {'auth': b64encode(token.encode('UTF-8')).decode('UTF-8')}}}
        # Create a new temp file with container auth data
        path = tempfile.mkdtemp(prefix=f'{registry_auth_prefix}{self.config.ident}_')
        register_for_cleanup(path)

        if self.config.process_isolation_executable == 'docker':
            auth_filename = 'config.json'
        else:
            auth_filename = 'auth.json'
        registry_auth_path = os.path.join(path, auth_filename)
        with open(registry_auth_path, 'w') as authfile:
            os.chmod(authfile.name, stat.S_IRUSR | stat.S_IWUSR)
            authfile.write(json.dumps(encoded_container_auth_data, indent=4))

        registries_conf_path = None
        if auth_data.get('verify_ssl', True) is False:
            registries_conf_path = os.path.join(path, 'registries.conf')

            with open(registries_conf_path, 'w') as registries_conf:
                os.chmod(registries_conf.name, stat.S_IRUSR | stat.S_IWUSR)

                lines = [
                    '[[registry]]',
                    f'location = "{host}"',
                    'insecure = true',
                ]

                registries_conf.write('\n'.join(lines))

        auth_path = authfile.name
        if self.config.process_isolation_executable == 'docker':
            auth_path = path  # docker expects to be passed directory
        return (auth_path, registries_conf_path)

    def _get_playbook_path(self, cmdline_args: list[str]) -> str | None:
        _playbook = ""
        _book_keeping_copy = cmdline_args.copy()
        for arg in cmdline_args:
            if arg in ['-i', '--inventory', '--inventory-file']:
                _book_keeping_copy_inventory_index = _book_keeping_copy.index(arg)
                _book_keeping_copy.pop(_book_keeping_copy_inventory_index)
                try:
                    _book_keeping_copy.pop(_book_keeping_copy_inventory_index)
                except IndexError:
                    # invalid command, pass through for execution
                    # to return correct error from ansible-core
                    return None

        if len(_book_keeping_copy) == 1:
            # it's probably safe to assume this is the playbook
            _playbook = _book_keeping_copy[0]
        elif _book_keeping_copy[0][0] != '-':
            # this should be the playbook, it's the only "naked" arg
            _playbook = _book_keeping_copy[0]
        else:
            # parse everything beyond the first arg because we checked that
            # in the previous case already
            for arg in _book_keeping_copy[1:]:
                if arg[0] == '-':
                    continue
                if _book_keeping_copy[(_book_keeping_copy.index(arg) - 1)][0] != '-':
                    _playbook = arg
                    break

        return _playbook
