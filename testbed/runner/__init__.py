from testbed.runner.spec import ScenarioSpec, load_matrix
from testbed.runner.stager import SMTPStager, StagedScenario, derive_client_tls_config
from testbed.runner.client import SMTPClient, ClientResult

__all__ = [
    "ScenarioSpec",
    "load_matrix",
    "SMTPStager",
    "StagedScenario",
    "derive_client_tls_config",
    "SMTPClient",
    "ClientResult",
    "ScenarioRunner",
    "ScenarioExecutionResult",
    "discover_docker_bridge",
]


def __getattr__(name: str):
    if name in ("ScenarioRunner", "ScenarioExecutionResult", "discover_docker_bridge"):
        import testbed.runner.runner as _r
        return getattr(_r, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


