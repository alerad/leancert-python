"""Bridge response validation without launching a bridge process."""

import gc
import io
import json
import threading
import weakref
from pathlib import Path
from types import SimpleNamespace

import pytest
from lean_runtime import EnvironmentError as RuntimeEnvironmentError

import leancert.client as client_module
from leancert.client import LeanClient
from leancert.exceptions import BridgeError, BridgeRemoteError, ProtocolViolation
from leancert.protocol import BridgeHandshake


class FakeSession:
    def __init__(self, responses: str):
        self.stdin = io.StringIO()
        self.stdout = io.StringIO(responses)
        self.stderr = io.StringIO()
        self.execution_id = "execution_test"
        self.running = True
        self.requests = []

    def poll(self):
        return None

    def request_line(self, line):
        if not self.running:
            raise RuntimeEnvironmentError("interactive process is not running")
        self.requests.append(line)
        self.stdin.write(line + "\n")
        response = self.stdout.readline()
        if not response:
            raise RuntimeEnvironmentError(
                "interactive process ended before producing a stdout response"
            )
        return response.removesuffix("\n").removesuffix("\r")

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
    with pytest.raises(BridgeError, match="response='not-json'"):
        client.ping()
    assert client._session is None


def test_multiple_calls_reuse_one_runtime_session():
    client = raw_client('{"id":1,"result":"pong"}\n{"id":2,"result":"pong"}\n')
    session = client._session

    assert client.ping() == "pong"
    assert client.ping() == "pong"
    assert client.execution_id == "execution_test"
    assert client._session is session
    assert len(session.requests) == 2


def test_client_finalizer_closes_abandoned_session():
    client = raw_client("")
    session = client._session
    client_ref = weakref.ref(client)

    del client
    gc.collect()

    assert session.running is False
    assert client_ref() is None


def test_runtime_transport_failure_retains_execution_diagnostic_and_retires_session():
    client = raw_client("")
    session = client._session

    def fail(_line):
        raise RuntimeEnvironmentError("interactive process ended")

    result = SimpleNamespace(
        exit_code=1,
        stdout="",
        stderr="",
        diagnostics=(SimpleNamespace(severity="error", message="checker initialization failed"),),
    )
    session.request_line = fail
    session.close = lambda: result

    with pytest.raises(BridgeError, match="execution_id=execution_test.*checker initialization"):
        client.ping()
    assert client.execution_result is result
    assert client._session is None


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
        description = SimpleNamespace(
            source_environment_id=None,
            source_revision=client_module.DEFAULT_BRIDGE_SOURCE_REVISION,
            toolchain="leanprover/lean4:v4.32.2",
            capability_id="sha256:" + "c" * 64,
            provenance={
                "lean.toolchain": "leanprover/lean4:v4.32.2",
                "leancert.bridge.revision": client_module.DEFAULT_BRIDGE_SOURCE_REVISION,
                "leancert.bridge.version": "test",
                "leancert.capability.digest": "sha256:" + "c" * 64,
                "leancert.core.revision": "d" * 40,
                "leancert.core.version": "test",
                "leancert.protocol.version": "3.0.0",
            },
        )

        def spawn_interactive(self, *, policy):
            assert policy.timeout_seconds == 3600
            return session

    class FakeRuntime:
        def __init__(self):
            self.environment_calls = 0

        def download_program(self, library, reference, *, expected_source_revision):
            assert library == client_module.DEFAULT_BRIDGE_PROGRAM_LIBRARY
            assert reference == client_module.DEFAULT_BRIDGE_PROGRAM_REFERENCE
            assert expected_source_revision == (
                None
                if reference.startswith("sha256:")
                else client_module.DEFAULT_BRIDGE_SOURCE_REVISION
            )
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


def test_ready_program_worker_clone_does_not_resolve_environment():
    program = SimpleNamespace(
        id="program_test",
        copy_id="sha256:" + "b" * 64,
        description=SimpleNamespace(provenance=None, source_environment_id=None),
    )

    class FakeRuntime:
        def open_references(self, *args, **kwargs):
            raise AssertionError("a ready-program worker must not resolve an environment")

    source = LeanClient(
        runtime=FakeRuntime(),
        program=program,
        require_program_profile=False,
    )
    worker = source._new_worker_client()

    assert worker is not source
    assert worker._program is program
    assert worker._environment is None
    assert worker.runtime is source.runtime
    assert worker.execution_policy is source.execution_policy


def test_environment_worker_clone_reuses_resolved_environment():
    environment = SimpleNamespace(id="environment_test")
    source = LeanClient(environment=environment)

    worker = source._new_worker_client()

    assert worker is not source
    assert worker._environment is environment
    assert worker._program is None


def test_digest_pinned_program_requires_content_addressed_stack_profile():
    class FakeProgram:
        description = SimpleNamespace(
            source_revision="a" * 40,
            toolchain="leanprover/lean4:v4.32.2",
            capability_id=None,
            provenance={},
        )

    client = LeanClient(
        program=FakeProgram(),
        program_reference="sha256:" + "b" * 64,
    )
    with pytest.raises(BridgeError, match="verified stack profile"):
        _ = client.program


def test_program_profile_must_match_live_handshake():
    info = json.loads(
        (Path(__file__).parent / "fixtures/bridge-contract-2.1/handshake.json").read_text(
            encoding="utf-8"
        )
    )
    contract = BridgeHandshake.parse(info)

    class FakeProgram:
        id = "program_" + "a" * 64
        copy_id = "sha256:" + "b" * 64
        description = SimpleNamespace(
            source_environment_id=None,
            source_revision="a" * 40,
            toolchain="leanprover/lean4:v4.32.2",
            capability_id=contract.capability_digest,
            provenance={
                "lean.toolchain": "leanprover/lean4:v4.32.2",
                "leancert.bridge.revision": "a" * 40,
                "leancert.bridge.version": "wrong",
                "leancert.capability.digest": contract.capability_digest,
                "leancert.core.revision": "c" * 40,
                "leancert.core.version": info["leancert_version"],
                "leancert.protocol.version": info["protocol_version"],
            },
        )

        def spawn_interactive(self, *, policy):
            response = json.dumps({"id": 1, "result": info}) + "\n"
            return FakeSession(response)

    client = LeanClient(
        program=FakeProgram(),
        program_reference="sha256:" + "b" * 64,
    )
    with pytest.raises(ProtocolViolation, match="bridge.version"):
        client.get_info()


@pytest.mark.parametrize("missing", ["verified", "computed_lo", "computed_hi"])
def test_check_bound_requires_complete_response(missing):
    result = {
        "verified": True,
        "computed_lo": {"n": 0, "d": 1},
        "computed_hi": {"n": 1, "d": 1},
    }
    result.pop(missing)

    client = raw_client(json.dumps({"id": 1, "result": result}) + "\n")
    with pytest.raises(BridgeError, match="missing"):
        client.check_bound({}, [], {"n": 1, "d": 1}, True)
