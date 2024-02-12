from ansible_runner.config._base import BaseConfig

from .docker import DockerEngine
from .podman import PodmanEngine


# A factory for creating our container engine.
#
# Although very simple now, we implement as a class, instead of
# a simple function, to allow for any unforeseen needed flexibility
# in the future.

class ContainerEngineFactory:
    def get_engine(self, engine_name: str, config: BaseConfig):
        if engine_name == "podman":
            return PodmanEngine(config)
        if engine_name == "docker":
            return DockerEngine(config)

        raise ValueError(engine_name)


engine_factory = ContainerEngineFactory()
