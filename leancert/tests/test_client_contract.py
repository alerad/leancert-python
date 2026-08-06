"""Bridge response validation without launching a bridge process."""

import io
import threading
from types import SimpleNamespace

import pytest
from lean_runtime import EnvironmentError as RuntimeEnvironmentError

import leancert.client as client_module
from leancert.client import LeanClient
from leancert.exceptions import BridgeError, BridgeRemoteError
from leancert.protocol import BridgeHandshake


class FakeSession:
    def __init__(self, responses: str):
        self.stdin = io.StringIO()
        self.stdout = io.StringIO(responses)
        self.stderr = io.StringIO()
        self.execution_id = "execution_test"
        self.running = True

    def poll(self):
        return None

    def close(self):
        self.running = False
        return SimpleNamespace(exit_code=0, stdout="", stderr="")


def raw_client(responses: str) -> LeanClient:
    client = LeanClient.__new__(LeanClient)
    client._session = FakeSession(responses)
    client.execution_result = None
    client._request_id = 0
    client._contract_checked = True
    client._bridge_info = {
        "bridge_api_version": "1.0.0",
        "bridge_version": "test",
        "lean_version": "4.31.0",
    }
    client._bridge_contract = BridgeHandshake.parse(client._bridge_info)
    client._io_lock = threading.RLock()
    client._environment = None
    client._program = None
    client.package_ref = "github:a/b@" + "a" * 40
    return client


def test_response_id_must_match_request():
    client = raw_client('{"id":99,"result":"pong"}\n')
    with pytest.raises(BridgeError, match="id mismatch"):
        client.ping()


def test_malformed_json_is_protocol_failure():
    client = raw_client("not-json\n")
    with pytest.raises(BridgeError, match="malformed JSON"):
        client.ping()


def test_response_envelope_has_exactly_one_payload():
    client = raw_client('{"id":1,"result":"pong","error":null}\n')
    with pytest.raises(BridgeError, match="exactly one"):
        client.ping()


def test_structured_remote_error_retains_code_and_data():
    client = raw_client(
        '{"id":1,"error":{"code":"invalid_params","message":"bad box","data":{"field":"box"}}}\n'
    )
    with pytest.raises(BridgeRemoteError) as captured:
        client.ping()
    assert captured.value.code == "invalid_params"
    assert captured.value.data == {"field": "box"}


def test_unadvertised_operation_is_rejected_before_write():
    client = raw_client("")
    client._bridge_info["operations"] = ["check_bound"]
    client._bridge_contract = BridgeHandshake.parse(client._bridge_info)

    with pytest.raises(BridgeError, match="does not advertise"):
        client.eval_interval({}, [])

    assert client._session.stdin.getvalue() == ""


def test_environment_resolution_is_lazy():
    class FakeRuntime:
        def __init__(self):
            self.calls = []

        def open_references(self, references, *, timeout):
            self.calls.append((references, timeout))
            return SimpleNamespace(id="environment_test")

    runtime = FakeRuntime()
    client = LeanClient(package_ref="github:a/b@v1", runtime=runtime, artifact_command=())
    assert runtime.calls == []
    assert client.environment_id is None
    assert client.environment.id == "environment_test"
    assert runtime.calls == [(["github:a/b@v1"], 3600.0)]


def test_default_runtime_prefers_leancert_and_shared_environment_libraries(monkeypatch):
    calls = []

    def runtime_factory(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace()

    monkeypatch.delenv("LEAN_RUNTIME_LIBRARIES", raising=False)
    monkeypatch.setattr(client_module, "Runtime", runtime_factory)

    client_module._new_default_runtime()

    assert calls == [{"libraries": client_module.DEFAULT_RUNTIME_LIBRARIES}]
    assert client_module.DEFAULT_RUNTIME_LIBRARIES == ("ghcr.io/alerad/leancert-runtime",)


def test_default_bridge_environment_uses_published_artifact_recipe():
    client = LeanClient(runtime=SimpleNamespace())

    assert client.artifact_command == (
        "lake",
        "exe",
        "@LeanCertBridge/lean_bridge_runtime_prepare",
    )


def test_explicit_runtime_library_environment_replaces_sdk_defaults(monkeypatch):
    calls = []

    def runtime_factory(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace()

    monkeypatch.setenv("LEAN_RUNTIME_LIBRARIES", "")
    monkeypatch.setattr(client_module, "Runtime", runtime_factory)

    client_module._new_default_runtime()

    assert calls == [{}]


def test_default_clients_share_one_resolved_environment(monkeypatch):
    class FakeRuntime:
        def __init__(self):
            self.calls = []

        def open_references(self, references, *, timeout):
            self.calls.append((references, timeout))
            return SimpleNamespace(id="environment_shared")

    runtime = FakeRuntime()
    monkeypatch.setattr(client_module, "_DEFAULT_RUNTIME", runtime)
    monkeypatch.setattr(client_module, "_DEFAULT_ENVIRONMENTS", {})
    first = LeanClient(package_ref="github:a/b@" + "a" * 40, artifact_command=())
    second = LeanClient(package_ref="github:a/b@" + "a" * 40, artifact_command=())

    assert first.environment is second.environment
    assert runtime.calls == [(["github:a/b@" + "a" * 40], 3600.0)]


def test_environment_resolution_timeout_is_configurable():
    class FakeRuntime:
        def __init__(self):
            self.timeout = None

        def open_references(self, references, *, timeout):
            assert references == ["github:a/b@v1"]
            self.timeout = timeout
            return SimpleNamespace(id="environment_test")

    runtime = FakeRuntime()
    client = LeanClient(
        package_ref="github:a/b@v1",
        runtime=runtime,
        resolution_timeout_seconds=7200,
        artifact_command=(),
    )
    assert client.environment.id == "environment_test"
    assert runtime.timeout == 7200.0


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), True])
def test_environment_resolution_timeout_must_be_positive_and_finite(timeout):
    with pytest.raises(ValueError, match="finite positive"):
        LeanClient(resolution_timeout_seconds=timeout)


def test_artifact_hydration_is_part_of_the_managed_environment_lock():
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class Package:
        artifact_command: tuple[str, ...] = ()

    @dataclass(frozen=True)
    class Spec:
        packages: tuple[Package, ...]

    class FakeRuntime:
        def __init__(self):
            self.resolved = None

        def environment(self, identifier):
            raise RuntimeEnvironmentError(f"unknown environment: {identifier}")

        def spec_from_references(self, references):
            assert references == ["github:a/b@v1"]
            return Spec((Package(),))

        def prepare(self, spec, *, timeout):
            self.resolved = (spec, timeout)
            return "locked"

        def open_exact(self, lock, *, name):
            assert lock == "locked"
            assert name.startswith("leancert-")
            return SimpleNamespace(id="environment_hydrated")

    runtime = FakeRuntime()
    client = LeanClient(
        package_ref="github:a/b@v1",
        runtime=runtime,
        artifact_command=("lake", "exe", "@LeanCertBridge/lean_bridge_runtime_prepare"),
    )
    assert client.environment.id == "environment_hydrated"
    spec, timeout = runtime.resolved
    assert spec.packages[0].artifact_command == (
        "lake",
        "exe",
        "@LeanCertBridge/lean_bridge_runtime_prepare",
    )
    assert timeout == 3600.0


def test_named_managed_environment_reopens_without_resolution():
    environment = SimpleNamespace(id="environment_cached")

    class FakeRuntime:
        def environment(self, identifier):
            assert identifier.startswith("leancert-")
            return environment

        def spec_from_references(self, references):
            raise AssertionError("a named cache hit must not resolve references")

    client = LeanClient(
        package_ref="github:a/b@v1", runtime=FakeRuntime(), artifact_command=("hydrate",)
    )
    assert client.environment is environment


def test_injected_environment_starts_managed_session():
    session = FakeSession('{"id":1,"result":"pong"}\n')

    class FakeEnvironment:
        id = "environment_test"

        def spawn_interactive(self, command, *, policy):
            assert command == ["lake", "exe", "@LeanCertBridge/lean_bridge"]
            assert policy.timeout_seconds == 3600
            return session

    client = LeanClient(environment=FakeEnvironment())
    assert client.ping() == "pong"
    assert client.execution_id == "execution_test"


def test_default_client_starts_from_ready_program_without_resolving_environment():
    session = FakeSession('{"id":1,"result":"pong"}\n')

    class FakeProgram:
        id = "program_" + "a" * 64
        copy_id = "sha256:" + "b" * 64
        description = SimpleNamespace(source_environment_id=None)

        def spawn_interactive(self, *, policy):
            assert policy.timeout_seconds == 3600
            return session

    class FakeRuntime:
        def __init__(self):
            self.environment_calls = 0

        def download_program(self, library, reference, *, expected_source_revision):
            assert library == client_module.DEFAULT_BRIDGE_PROGRAM_LIBRARY
            assert reference == client_module.DEFAULT_BRIDGE_PROGRAM_REFERENCE
            assert expected_source_revision == client_module.DEFAULT_BRIDGE_SOURCE_REVISION
            return FakeProgram()

        def open_references(self, *args, **kwargs):
            self.environment_calls += 1
            raise AssertionError("ordinary proof execution must not hydrate a full environment")

    runtime = FakeRuntime()
    client = LeanClient(runtime=runtime)
    assert client.ping() == "pong"
    assert client.program_id == "program_" + "a" * 64
    assert client.environment_id is None
    assert runtime.environment_calls == 0


@pytest.mark.parametrize("missing", ["verified", "computed_lo", "computed_hi"])
def test_check_bound_requires_complete_response(missing):
    result = {
        "verified": True,
        "computed_lo": {"n": 0, "d": 1},
        "computed_hi": {"n": 1, "d": 1},
    }
    result.pop(missing)
    import json

    client = raw_client(json.dumps({"id": 1, "result": result}) + "\n")
    with pytest.raises(BridgeError, match="missing"):
        client.check_bound({}, [], {"n": 1, "d": 1}, True)
