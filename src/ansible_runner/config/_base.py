############################
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

# pylint: disable=W0201

from __future__ import annotations

import logging
import os
import re
import tempfile
import shutil
from enum import Enum
from uuid import uuid4
from collections.abc import Mapping
from typing import Any

import pexpect

from ansible_runner import defaults
from ansible_runner.containers import engine_factory
from ansible_runner.output import debug
from ansible_runner.exceptions import ConfigurationError
from ansible_runner.loader import ArtifactLoader
from ansible_runner.utils import (
    get_callback_dir,
    open_fifo_write,
    args2cmdline,
    sanitize_container_name,
)

logger = logging.getLogger('ansible-runner')


class BaseExecutionMode(Enum):
    NONE = 0
    # run ansible commands either locally or within EE
    ANSIBLE_COMMANDS = 1
    # execute generic commands
    GENERIC_COMMANDS = 2


class BaseConfig:

    def __init__(self,
                 private_data_dir: str | None = None,
                 host_cwd: str | None = None,
                 envvars: dict[str, Any] | None = None,
                 passwords=None,
                 settings=None,
                 project_dir: str | None = None,
                 artifact_dir: str | None = None,
                 fact_cache_type: str = 'jsonfile',
                 fact_cache=None,
                 process_isolation: bool = False,
                 process_isolation_executable: str | None = None,
                 container_image: str = "",
                 container_volume_mounts=None,
                 container_options=None,
                 container_workdir: str | None = None,
                 container_auth_data=None,
                 ident: str | None = None,
                 rotate_artifacts: int = 0,
                 timeout: int | None = None,
                 ssh_key: str | None = None,
                 quiet: bool = False,
                 json_mode: bool = False,
                 check_job_event_data: bool = False,
                 suppress_env_files: bool = False,
                 keepalive_seconds: int | None = None
                 ):
        # pylint: disable=W0613

        # common params
        self.host_cwd = host_cwd
        self.envvars = envvars
        self.ssh_key_data = ssh_key
        self.command: list[str] = []

        # container params
        self.process_isolation = process_isolation
        self.process_isolation_executable = process_isolation_executable or defaults.default_process_isolation_executable
        self.container_image = container_image
        self.container_volume_mounts = container_volume_mounts
        self.container_workdir = container_workdir
        self.container_auth_data = container_auth_data
        self.registry_auth_path: str
        self.container_name: str = ""  # like other properties, not accurate until prepare is called
        self.container_options = container_options

        # runner params
        self.rotate_artifacts = rotate_artifacts
        self.quiet = quiet
        self.json_mode = json_mode
        self.passwords = passwords
        self.settings = settings
        self.timeout = timeout
        self.check_job_event_data = check_job_event_data
        self.suppress_env_files = suppress_env_files
        # ignore this for now since it's worker-specific and would just trip up old runners
        # self.keepalive_seconds = keepalive_seconds

        # setup initial environment
        if private_data_dir:
            self.private_data_dir = os.path.abspath(private_data_dir)
            # Note that os.makedirs, exist_ok=True is dangerous.  If there's a directory writable
            # by someone other than the user anywhere in the path to be created, an attacker can
            # attempt to compromise the directories via a race.
            os.makedirs(self.private_data_dir, exist_ok=True, mode=0o700)
        else:
            self.private_data_dir = tempfile.mkdtemp(prefix=defaults.AUTO_CREATE_NAMING, dir=defaults.AUTO_CREATE_DIR)

        if artifact_dir is None:
            artifact_dir = os.path.join(self.private_data_dir, 'artifacts')
        else:
            artifact_dir = os.path.abspath(artifact_dir)

        if ident is None:
            self.ident = str(uuid4())
        else:
            self.ident = str(ident)

        self.artifact_dir = os.path.join(artifact_dir, self.ident)

        if not project_dir:
            self.project_dir = os.path.join(self.private_data_dir, 'project')
        else:
            self.project_dir = project_dir

        self.rotate_artifacts = rotate_artifacts
        self.fact_cache_type = fact_cache_type
        self.fact_cache = os.path.join(self.artifact_dir, fact_cache or 'fact_cache') if self.fact_cache_type == 'jsonfile' else None

        self.loader = ArtifactLoader(self.private_data_dir)

        if self.host_cwd:
            self.host_cwd = os.path.abspath(self.host_cwd)
            self.cwd = self.host_cwd
        else:
            self.cwd = os.getcwd()

        os.makedirs(self.artifact_dir, exist_ok=True, mode=0o700)

    _CONTAINER_ENGINES = ('docker', 'podman')

    @property
    def containerized(self):
        return self.process_isolation and self.process_isolation_executable in self._CONTAINER_ENGINES

    def prepare_env(self, runner_mode: str = 'pexpect') -> None:
        """
        Manages reading environment metadata files under ``private_data_dir`` and merging/updating
        with existing values so the :py:class:`ansible_runner.runner.Runner` object can read and use them easily
        """
        self.runner_mode = runner_mode
        try:
            if self.settings and isinstance(self.settings, dict):
                self.settings.update(self.loader.load_file('env/settings', Mapping))  # type: ignore
            else:
                self.settings = self.loader.load_file('env/settings', Mapping)
        except ConfigurationError:
            debug("Not loading settings")
            self.settings = {}

        if self.runner_mode == 'pexpect':
            try:
                if self.passwords and isinstance(self.passwords, dict):
                    self.passwords.update(self.loader.load_file('env/passwords', Mapping))  # type: ignore
                else:
                    self.passwords = self.passwords or self.loader.load_file('env/passwords', Mapping)
            except ConfigurationError:
                debug('Not loading passwords')

            self.expect_passwords = {}
            try:
                if self.passwords:
                    self.expect_passwords = {
                        re.compile(pattern, re.M): password
                        for pattern, password in self.passwords.items()
                    }
            except Exception as e:
                debug(f'Failed to compile RE from passwords: {e}')

            self.expect_passwords[pexpect.TIMEOUT] = None
            self.expect_passwords[pexpect.EOF] = None

            self.pexpect_timeout = self.settings.get('pexpect_timeout', 5)
            self.pexpect_use_poll = self.settings.get('pexpect_use_poll', True)
            self.idle_timeout = self.settings.get('idle_timeout', None)

            if self.timeout:
                self.job_timeout = int(self.timeout)
            else:
                self.job_timeout = self.settings.get('job_timeout', None)

        elif self.runner_mode == 'subprocess':
            if self.timeout:
                self.subprocess_timeout = int(self.timeout)
            else:
                self.subprocess_timeout = self.settings.get('subprocess_timeout', None)

        self.process_isolation = self.settings.get('process_isolation', self.process_isolation)
        self.process_isolation_executable = self.settings.get('process_isolation_executable', self.process_isolation_executable)

        self.container_image = self.settings.get('container_image', self.container_image)
        self.container_volume_mounts = self.settings.get('container_volume_mounts', self.container_volume_mounts)
        self.container_options = self.settings.get('container_options', self.container_options)
        self.container_auth_data = self.settings.get('container_auth_data', self.container_auth_data)

        if self.containerized:
            if not self.container_image:
                raise ConfigurationError(
                    f'container_image required when specifying process_isolation_executable={self.process_isolation_executable}'
                )
            self.container_name = f"ansible_runner_{sanitize_container_name(self.ident)}"
            self.env: dict[str, Any] = {}

            if self.process_isolation_executable == 'podman':
                # A kernel bug in RHEL < 8.5 causes podman to use the fuse-overlayfs driver. This results in errors when
                # trying to set extended file attributes. Setting this environment variable allows modules to take advantage
                # of a fallback to work around this bug when failures are encountered.
                #
                # See the following for more information:
                #    https://github.com/ansible/ansible/pull/73282
                #    https://github.com/ansible/ansible/issues/73310
                #    https://issues.redhat.com/browse/AAP-476
                self.env['ANSIBLE_UNSAFE_WRITES'] = '1'

            artifact_dir = os.path.join("/runner/artifacts", self.ident)
            self.env['AWX_ISOLATED_DATA_DIR'] = artifact_dir
            if self.fact_cache_type == 'jsonfile':
                self.env['ANSIBLE_CACHE_PLUGIN_CONNECTION'] = os.path.join(artifact_dir, 'fact_cache')

        else:
            # seed env with existing shell env
            self.env = os.environ.copy()

        if self.envvars and isinstance(self.envvars, dict):
            self.env.update(self.envvars)

        try:
            envvars = self.loader.load_file('env/envvars', Mapping)
            if envvars:
                self.env.update(envvars)  # type: ignore
        except ConfigurationError:
            debug("Not loading environment vars")
            # Still need to pass default environment to pexpect

        try:
            if self.ssh_key_data is None:
                self.ssh_key_data = self.loader.load_file('env/ssh_key', str)  # type: ignore
        except ConfigurationError:
            debug("Not loading ssh key")
            self.ssh_key_data = None

        # write the SSH key data into a fifo read by ssh-agent
        if self.ssh_key_data:
            self.ssh_key_path = os.path.join(self.artifact_dir, 'ssh_key_data')
            open_fifo_write(self.ssh_key_path, self.ssh_key_data)

        self.suppress_output_file = self.settings.get('suppress_output_file', False)
        self.suppress_ansible_output = self.settings.get('suppress_ansible_output', self.quiet)

        if 'fact_cache' in self.settings:
            if 'fact_cache_type' in self.settings:
                if self.settings['fact_cache_type'] == 'jsonfile':
                    self.fact_cache = os.path.join(self.artifact_dir, self.settings['fact_cache'])
            else:
                self.fact_cache = os.path.join(self.artifact_dir, self.settings['fact_cache'])

        # Use local callback directory
        if self.containerized:
            # when containerized, copy the callback dir to $private_data_dir/artifacts/<job_id>/callback
            # then append to env['ANSIBLE_CALLBACK_PLUGINS'] with the copied location.
            callback_dir = os.path.join(self.artifact_dir, 'callback')
            # if callback dir already exists (on repeat execution with the same ident), remove it first.
            if os.path.exists(callback_dir):
                shutil.rmtree(callback_dir)
            shutil.copytree(get_callback_dir(), callback_dir)

            container_callback_dir = os.path.join("/runner/artifacts", self.ident, "callback")
            self.env['ANSIBLE_CALLBACK_PLUGINS'] = ':'.join(filter(None, (self.env.get('ANSIBLE_CALLBACK_PLUGINS'), container_callback_dir)))
        else:
            callback_dir = self.env.get('AWX_LIB_DIRECTORY', os.getenv('AWX_LIB_DIRECTORY', ''))
            if not callback_dir:
                callback_dir = get_callback_dir()
            self.env['ANSIBLE_CALLBACK_PLUGINS'] = ':'.join(filter(None, (self.env.get('ANSIBLE_CALLBACK_PLUGINS'), callback_dir)))

        # this is an adhoc command if the module is specified, TODO: combine with logic in RunnerConfig class
        is_adhoc = bool((getattr(self, 'binary', None) is None) and (getattr(self, 'module', None) is not None))

        if self.env.get('ANSIBLE_STDOUT_CALLBACK'):
            self.env['ORIGINAL_STDOUT_CALLBACK'] = self.env.get('ANSIBLE_STDOUT_CALLBACK')

        if is_adhoc:
            # force loading awx_display stdout callback for adhoc commands
            self.env["ANSIBLE_LOAD_CALLBACK_PLUGINS"] = '1'
            if 'AD_HOC_COMMAND_ID' not in self.env:
                self.env['AD_HOC_COMMAND_ID'] = '1'

        self.env['ANSIBLE_STDOUT_CALLBACK'] = 'awx_display'

        self.env['ANSIBLE_RETRY_FILES_ENABLED'] = 'False'
        if 'ANSIBLE_HOST_KEY_CHECKING' not in self.env:
            self.env['ANSIBLE_HOST_KEY_CHECKING'] = 'False'
        if not self.containerized:
            self.env['AWX_ISOLATED_DATA_DIR'] = self.artifact_dir

        if self.fact_cache_type == 'jsonfile':
            self.env['ANSIBLE_CACHE_PLUGIN'] = 'jsonfile'
            if not self.containerized:
                self.env['ANSIBLE_CACHE_PLUGIN_CONNECTION'] = self.fact_cache

        # Pexpect will error with non-string envvars types, so we ensure string types
        self.env = {str(k): str(v) for k, v in self.env.items()}

        debug('env:')
        for k, v in sorted(self.env.items()):
            debug(f' {k}: {v}')

    def handle_command_wrap(self, execution_mode: BaseExecutionMode, cmdline_args: list[str]) -> None:
        if self.ssh_key_data:
            logger.debug('ssh key data added')
            self.command = self.wrap_args_with_ssh_agent(self.command, self.ssh_key_path)

        if self.containerized:
            logger.debug('containerization enabled')
            self.command = self.wrap_args_for_containerization(self.command, execution_mode, cmdline_args)
        else:
            logger.debug('containerization disabled')

        if hasattr(self, 'command') and isinstance(self.command, list):
            logger.debug("command: %s", ' '.join(self.command))

    def wrap_args_for_containerization(self,
                                       args: list[str],
                                       execution_mode: BaseExecutionMode,
                                       cmdline_args: list[str],
                                       ) -> list[str]:
        """
        :param list[str] args: The currently built command to execute.
        :param BaseExecutionMode execution_mode: How we are currently being executed.
        :param list[str] cmdline_args: A list of arguments to be passed to the executable command.
        """
        engine = engine_factory.get_engine(self.process_isolation_executable, self)
        new_args = engine.default_args(args, execution_mode, cmdline_args)
        logger.debug("container engine invocation: %s", ' '.join(new_args))
        return new_args

    def wrap_args_with_ssh_agent(self,
                                 args: list[str],
                                 ssh_key_path: str | None,
                                 ssh_auth_sock: str | None = None,
                                 silence_ssh_add: bool = False
                                 ) -> list[str]:
        """
        Given an existing command line and parameterization this will return the same command line wrapped with the
        necessary calls to ``ssh-agent``
        """
        if self.containerized:
            artifact_dir = os.path.join("/runner/artifacts", self.ident)
            ssh_key_path = os.path.join(artifact_dir, "ssh_key_data")

        if ssh_key_path:
            ssh_add_command = args2cmdline('ssh-add', ssh_key_path)
            if silence_ssh_add:
                ssh_add_command = ' '.join([ssh_add_command, '2>/dev/null'])
            ssh_key_cleanup_command = f'rm -f {ssh_key_path}'
            # The trap ensures the fifo is cleaned up even if the call to ssh-add fails.
            # This prevents getting into certain scenarios where subsequent reads will
            # hang forever.
            cmd = ' && '.join([args2cmdline('trap', ssh_key_cleanup_command, 'EXIT'),
                               ssh_add_command,
                               ssh_key_cleanup_command,
                               args2cmdline(*args)])
            args = ['ssh-agent']
            if ssh_auth_sock:
                args.extend(['-a', ssh_auth_sock])
            args.extend(['sh', '-c', cmd])
        return args
