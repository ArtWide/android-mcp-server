"""Tests for ScreenMirrorManager (scrcpy live mirror)."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import screenmirror
from screenmirror import ScreenMirrorManager


def _manager(tmp_path, serial="devA"):
    dm = MagicMock()
    dm.device.serial = serial
    return ScreenMirrorManager(dm, output_dir=str(tmp_path))


class _FakeProc:
    def __init__(self, alive=True, pid=4242):
        self._alive = alive
        self.pid = pid
        self.terminated = False
    def poll(self):
        return None if self._alive else 0
    def terminate(self):
        self.terminated = True
        self._alive = False
    def wait(self, timeout=None):
        return 0
    def kill(self):
        self._alive = False


class TestStart:
    def test_missing_scrcpy_raises(self, tmp_path):
        mgr = _manager(tmp_path)
        with patch.object(screenmirror, "_discover_scrcpy", return_value=None):
            with pytest.raises(RuntimeError) as exc:
                mgr.start()
        assert "scrcpy not found" in str(exc.value)

    def test_start_builds_command_for_active_device(self, tmp_path):
        mgr = _manager(tmp_path, serial="1.2.3.4:5555")
        proc = _FakeProc(alive=True)
        with patch.object(screenmirror, "_discover_scrcpy", return_value="scrcpy"), \
                patch.object(screenmirror.subprocess, "Popen", return_value=proc) as popen, \
                patch.object(screenmirror.time, "sleep"):
            out = mgr.start(max_size=1024)
        cmd = popen.call_args[0][0]
        assert cmd[0] == "scrcpy"
        assert "-s" in cmd and "1.2.3.4:5555" in cmd          # active device
        assert "--max-size" in cmd and "1024" in cmd
        assert "started" in out and mgr.is_running()

    def test_record_adds_output_path(self, tmp_path):
        mgr = _manager(tmp_path)
        proc = _FakeProc(alive=True)
        with patch.object(screenmirror, "_discover_scrcpy", return_value="scrcpy"), \
                patch.object(screenmirror.subprocess, "Popen", return_value=proc), \
                patch.object(screenmirror.time, "sleep"):
            out = mgr.start(record=True)
        assert mgr._record_path is not None
        assert mgr._record_path.suffix == ".mp4"
        assert "Recording" in out

    def test_immediate_exit_surfaces_log(self, tmp_path):
        mgr = _manager(tmp_path)
        proc = _FakeProc(alive=False)  # scrcpy died right away

        def fake_popen(cmd, stdout=None, stderr=None):
            # emulate scrcpy writing an error to its log then exiting (flush like
            # a real child process closing its inherited stdout).
            stdout.write("ERROR: could not find device\n")
            stdout.flush()
            return proc
        with patch.object(screenmirror, "_discover_scrcpy", return_value="scrcpy"), \
                patch.object(screenmirror.subprocess, "Popen", side_effect=fake_popen), \
                patch.object(screenmirror.time, "sleep"):
            with pytest.raises(RuntimeError) as exc:
                mgr.start()
        assert "exited immediately" in str(exc.value)
        assert "could not find device" in str(exc.value)
        assert not mgr.is_running()

    def test_start_twice_is_guarded(self, tmp_path):
        mgr = _manager(tmp_path)
        proc = _FakeProc(alive=True)
        with patch.object(screenmirror, "_discover_scrcpy", return_value="scrcpy"), \
                patch.object(screenmirror.subprocess, "Popen", return_value=proc), \
                patch.object(screenmirror.time, "sleep"):
            mgr.start()
            out2 = mgr.start()
        assert "already running" in out2


class TestStopStatus:
    def test_stop_terminates(self, tmp_path):
        mgr = _manager(tmp_path)
        proc = _FakeProc(alive=True)
        with patch.object(screenmirror, "_discover_scrcpy", return_value="scrcpy"), \
                patch.object(screenmirror.subprocess, "Popen", return_value=proc), \
                patch.object(screenmirror.time, "sleep"):
            mgr.start()
        out = mgr.stop()
        assert proc.terminated
        assert "stopped" in out
        assert not mgr.is_running()

    def test_stop_when_not_running(self, tmp_path):
        mgr = _manager(tmp_path)
        assert "was not running" in mgr.stop()

    def test_status_strings(self, tmp_path):
        mgr = _manager(tmp_path)
        assert "not running" in mgr.status()
        proc = _FakeProc(alive=True)
        with patch.object(screenmirror, "_discover_scrcpy", return_value="scrcpy"), \
                patch.object(screenmirror.subprocess, "Popen", return_value=proc), \
                patch.object(screenmirror.time, "sleep"):
            mgr.start()
        assert "RUNNING" in mgr.status()


class TestDiscover:
    def test_env_var_file(self, tmp_path):
        exe = tmp_path / "scrcpy.exe"
        exe.write_text("x")
        with patch.dict(os.environ, {"SCRCPY_PATH": str(exe)}):
            assert screenmirror._discover_scrcpy() == str(exe)
