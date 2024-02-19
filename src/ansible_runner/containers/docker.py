import os

from ansible_runner.containers.base import BaseEngine


class DockerEngine(BaseEngine):
    def extra_arguments(self) -> list[str]:
        return [
            f'--user={os.getuid()}',
        ]
