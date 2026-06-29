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

    def test_list_flows_no_file(self, tmp_path):
        mgr = _mgr(tmp_path)
        assert "No capture file" in mgr.list_flows()

    def test_status_not_running(self, tmp_path):
        mgr = _mgr(tmp_path)
        assert "not running" in mgr.status()
