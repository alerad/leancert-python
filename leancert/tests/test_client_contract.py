"""Bridge response validation without launching a bridge process."""

import io
import os
import threading

import pytest

from leancert.client import LeanClient
from leancert.exceptions import BridgeError, BridgeRemoteError
from leancert.protocol import BridgeHandshake


class FakeProcess:
    def __init__(self, responses: str):
        self.stdin = io.StringIO()
        self.stdout = io.StringIO(responses)
        self.stderr = io.StringIO()

    def poll(self):
        return None


def raw_client(responses: str) -> LeanClient:
    client = LeanClient.__new__(LeanClient)
    client.binary_path = "unused"
    client._process = FakeProcess(responses)
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
        '{"id":1,"error":{"code":"invalid_params","message":"bad box",'
        '"data":{"field":"box"}}}\n'
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

    assert client._process.stdin.getvalue() == ""


def test_binary_discovery_does_not_implicitly_use_sibling_checkout(tmp_path, monkeypatch):
    package = tmp_path / "python" / "leancert"
    package.mkdir(parents=True)
    sibling = tmp_path / "python" / "leancert-bridge" / ".lake" / "build" / "bin"
    sibling.mkdir(parents=True)
    (sibling / "lean_bridge").write_text("development binary")
    monkeypatch.setattr("leancert.client.__file__", str(package / "client.py"))
    monkeypatch.chdir(tmp_path / "python")
    monkeypatch.delenv("LEANCERT_BRIDGE_PATH", raising=False)
    monkeypatch.setattr("leancert.client.shutil.which", lambda name: None)

    with pytest.raises(FileNotFoundError):
        LeanClient()


def test_explicit_environment_bridge_remains_supported(tmp_path, monkeypatch):
    binary = tmp_path / "lean_bridge"
    binary.write_text("explicit binary")
    monkeypatch.setenv("LEANCERT_BRIDGE_PATH", os.fspath(binary))
    assert LeanClient().binary_path == os.fspath(binary)


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
