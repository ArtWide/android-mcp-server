"""
Tests for NetworkCaptureManager. mitmdump, adb, and the device are mocked.
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import networkmanager
from networkmanager import NetworkCaptureManager


def _mgr(tmp_path):
    dm = MagicMock()
    dm.device.serial = "serial123"
    return NetworkCaptureManager(dm, output_dir=str(tmp_path))


class TestStartStop:
    def test_start_requires_mitmdump(self, tmp_path):
        mgr = _mgr(tmp_path)
        with patch("networkmanager._discover_mitmdump", return_value=None):
            with pytest.raises(RuntimeError) as exc:
                mgr.start_capture()
        assert "mitmdump not found" in str(exc.value)

    def test_start_sets_proxy_and_reverse(self, tmp_path):
        mgr = _mgr(tmp_path)
        proc = MagicMock()
        proc.poll.return_value = None
        proc.pid = 4321
        with patch("networkmanager._discover_mitmdump", return_value="mitmdump"), \
                patch("networkmanager.subprocess.Popen", return_value=proc), \
                patch.object(mgr, "_adb", return_value=MagicMock(returncode=0)) as adb:
            out = mgr.start_capture(port=8080)
        assert "started on port 8080" in out
        # adb reverse was set up
        adb.assert_any_call("reverse", "tcp:8080", "tcp:8080")
        # device proxy set
        mgr.device_manager.execute_adb_shell_command.assert_any_call(
            "settings put global http_proxy 127.0.0.1:8080")
        assert mgr.is_running()

    def test_start_when_already_running(self, tmp_path):
        mgr = _mgr(tmp_path)
        proc = MagicMock(); proc.poll.return_value = None
        mgr._proc = proc; mgr._port = 8080
        out = mgr.start_capture()
        assert "already running" in out

    def test_stop_clears_proxy(self, tmp_path):
        mgr = _mgr(tmp_path)
        proc = MagicMock(); proc.poll.return_value = None
        mgr._proc = proc; mgr._port = 8080
        with patch.object(mgr, "_adb", return_value=MagicMock(returncode=0)):
            out = mgr.stop_capture()
        proc.terminate.assert_called_once()
        mgr.device_manager.execute_adb_shell_command.assert_any_call(
            "settings put global http_proxy :0")
        assert "stopped" in out
        assert not mgr.is_running()


class TestFlows:
    def test_list_flows_reads_jsonl(self, tmp_path):
        mgr = _mgr(tmp_path)
        mgr.workdir.mkdir(parents=True, exist_ok=True)
        mgr._flowfile = mgr.workdir / "flows-8080.jsonl"
        with open(mgr._flowfile, "w", encoding="utf-8") as f:
            f.write(json.dumps({"method": "GET", "url": "https://a.com/x",
                                "status": 200, "resp_len": 12,
                                "content_type": "text/html"}) + "\n")
            f.write(json.dumps({"method": "POST", "url": "https://a.com/login",
                                "status": 401, "resp_len": 5,
                                "content_type": "application/json"}) + "\n")
        out = mgr.list_flows()
        assert "GET https://a.com/x" in out
        assert "401  POST https://a.com/login" in out
        # flows are numbered so network_get_flow can address them
        assert "[1]" in out and "[2]" in out

    def test_list_flows_no_file(self, tmp_path):
        mgr = _mgr(tmp_path)
        assert "No capture file" in mgr.list_flows()

    def test_get_flow_returns_headers_and_body(self, tmp_path):
        mgr = _mgr(tmp_path)
        mgr.workdir.mkdir(parents=True, exist_ok=True)
        mgr._flowfile = mgr.workdir / "flows-8080.jsonl"
        with open(mgr._flowfile, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "method": "POST", "url": "https://api.example.com/device",
                "http_version": "HTTP/1.1", "status": 200, "reason": "OK",
                "req_headers": [["Host", "api.example.com"],
                                ["Content-Type", "application/json"]],
                "req_body": {"text": '{"udid":"abc"}', "b64": None,
                             "len": 14, "truncated": False},
                "resp_headers": [["Content-Type", "application/json"]],
                "resp_body": {"text": '{"ok":true}', "b64": None,
                              "len": 11, "truncated": False},
            }) + "\n")
        out = mgr.get_flow(1)
        assert "POST https://api.example.com/device HTTP/1.1" in out
        assert "Host: api.example.com" in out
        assert '{"udid":"abc"}' in out
        assert "Response  200 OK" in out
        assert '{"ok":true}' in out

    def test_get_flow_binary_body_and_truncation(self, tmp_path):
        mgr = _mgr(tmp_path)
        mgr.workdir.mkdir(parents=True, exist_ok=True)
        mgr._flowfile = mgr.workdir / "flows-8080.jsonl"
        with open(mgr._flowfile, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "method": "GET", "url": "https://a.com/img", "status": 200,
                "req_headers": [], "req_body": {"text": None, "b64": None,
                                                "len": 0, "truncated": False},
                "resp_headers": [], "resp_body": {"text": None, "b64": "QUJD",
                                                  "len": 99999, "truncated": True},
            }) + "\n")
        out = mgr.get_flow(1)
        assert "Request body --- (empty)" in out
        assert "[truncated]" in out
        assert "base64) QUJD" in out

    def test_get_flow_out_of_range(self, tmp_path):
        mgr = _mgr(tmp_path)
        mgr.workdir.mkdir(parents=True, exist_ok=True)
        mgr._flowfile = mgr.workdir / "flows-8080.jsonl"
        mgr._flowfile.write_text(json.dumps({"method": "GET", "url": "u",
                                             "status": 200}) + "\n",
                                 encoding="utf-8")
        assert "out of range" in mgr.get_flow(5)

    def test_get_flow_no_file(self, tmp_path):
        mgr = _mgr(tmp_path)
        assert "No capture file" in mgr.get_flow(1)

    def test_status_not_running(self, tmp_path):
        mgr = _mgr(tmp_path)
        assert "not running" in mgr.status()
