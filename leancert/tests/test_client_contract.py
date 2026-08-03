"""Bridge response validation without launching a bridge process."""

import io
import threading
from types import SimpleNamespace

import pytest

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

        def ensure_references(self, references):
            self.calls.append(references)
            return SimpleNamespace(id="environment_test")

    runtime = FakeRuntime()
    client = LeanClient(package_ref="github:a/b@v1", runtime=runtime)
    assert runtime.calls == []
    assert client.environment_id == "environment_test"
    assert runtime.calls == [["github:a/b@v1"]]


def test_default_clients_share_one_resolved_environment(monkeypatch):
    class FakeRuntime:
        def __init__(self):
            self.calls = []

        def ensure_references(self, references):
            self.calls.append(references)
            return SimpleNamespace(id="environment_shared")

    runtime = FakeRuntime()
    monkeypatch.setattr(client_module, "_DEFAULT_RUNTIME", runtime)
    monkeypatch.setattr(client_module, "_DEFAULT_ENVIRONMENTS", {})
    first = LeanClient(package_ref="github:a/b@" + "a" * 40)
    second = LeanClient(package_ref="github:a/b@" + "a" * 40)

    assert first.environment is second.environment
    assert runtime.calls == [["github:a/b@" + "a" * 40]]


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
