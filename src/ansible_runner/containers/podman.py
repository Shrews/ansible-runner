from ansible_runner.containers.base import BaseEngine


class PodmanEngine(BaseEngine):
    def extra_arguments(self) -> list[str]:
        return [
            '--quiet',
        ]
