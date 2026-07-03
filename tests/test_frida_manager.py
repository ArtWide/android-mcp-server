"""
Tests for FridaManager. The frida module and the device are mocked, so these
run without frida-server or a real device.
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fridamanager
from fridamanager import FridaManager


def _manager_with_device(mock_device):
    device_manager = MagicMock()
    device_manager.device.serial = "serial123"
    mgr = FridaManager(device_manager)
    # Bypass real frida device resolution
    mgr._get_device = MagicMock(return_value=mock_device)
    return mgr


class TestFridaUnavailable:
    def test_require_frida_raises_hint(self):
        device_manager = MagicMock()
        mgr = FridaManager(device_manager)
        with patch.object(fridamanager, "frida", None), \
                patch.object(fridamanager, "_FRIDA_IMPORT_ERROR", ImportError("no frida")):
            with pytest.raises(RuntimeError) as exc:
                mgr._require_frida()
        assert "Frida is not available" in str(exc.value)


class TestEnumeration:
    def test_list_processes(self):
        device = MagicMock()
        # NOTE: `name` is a reserved MagicMock kwarg; set it as an attribute.
        p1 = MagicMock(pid=100)
        p1.name = "zygote"
        p2 = MagicMock(pid=200)
        p2.name = "com.example.app"
        device.enumerate_processes.return_value = [p1, p2]
        mgr = _manager_with_device(device)
        out = mgr.list_processes()
        assert "100\tzygote" in out
        assert "200\tcom.example.app" in out

    def test_list_applications(self):
        device = MagicMock()
        a1 = MagicMock(identifier="com.example.app", pid=0)
        a1.name = "Example"
        device.enumerate_applications.return_value = [a1]
        mgr = _manager_with_device(device)
        out = mgr.list_applications()
        assert "com.example.app" in out
        assert out.startswith("-\t")  # pid 0 -> '-'


class TestCompatibility:
    def test_server_missing(self):
        dm = MagicMock()
        dm.execute_adb_shell_command.return_value = ""
        mgr = FridaManager(dm)
        out = mgr.check_compatibility()
        assert "not found" in out

    def test_mismatch_reported(self):
        dm = MagicMock()
        def shell(cmd):
            if "ps" in cmd:
                return "u0_a1 1234 frida-server"
            if "ls -l" in cmd:
                return "-rwxr-xr-x 1 root root 100 frida-server"
            if "--version" in cmd:
                return "16.1.4"
            return ""
        dm.execute_adb_shell_command.side_effect = shell
        mgr = FridaManager(dm)
        with patch.object(fridamanager, "frida") as fake:
            fake.__version__ = "17.15.3"
            out = mgr.check_compatibility()
        assert "Device frida-server version: 16.1.4" in out
        assert "MISMATCH" in out

    def test_exact_match(self):
        dm = MagicMock()
        def shell(cmd):
            if "ls -l" in cmd:
                return "-rwxr-xr-x frida-server"
            if "--version" in cmd:
                return "17.15.3"
            return ""
        dm.execute_adb_shell_command.side_effect = shell
        mgr = FridaManager(dm)
        with patch.object(fridamanager, "frida") as fake:
            fake.__version__ = "17.15.3"
            out = mgr.check_compatibility()
        assert "MATCH (exact)" in out


class TestPreset:
    def test_unknown_preset_raises(self):
        mgr = FridaManager(MagicMock())
        with pytest.raises(RuntimeError) as exc:
            mgr.run_preset("sid", "does-not-exist")
        assert "not found" in str(exc.value)

    def test_known_preset_loads(self):
        mgr = FridaManager(MagicMock())
        with patch.object(mgr, "run_script", return_value="loaded") as rs:
            mgr.run_preset("sid", "ssl-unpin")
        rs.assert_called_once()
        assert "Java.perform" in rs.call_args[0][1]


class TestSessionLifecycle:
    def _device_with_session(self):
        device = MagicMock()
        session = MagicMock()
        device.attach.return_value = session
        return device, session

    def test_attach_returns_session_id(self):
        device, session = self._device_with_session()
        mgr = _manager_with_device(device)
        out = mgr.attach("com.example.app")
        assert "session_id=" in out
        device.attach.assert_called_once()
        # one registered session
        assert len(mgr._sessions) == 1

    def test_attach_numeric_target_uses_int_pid(self):
        device, session = self._device_with_session()
        mgr = _manager_with_device(device)
        mgr.attach("1234")
        device.attach.assert_called_once_with(1234)

    def test_spawn_registers_pid(self):
        device, session = self._device_with_session()
        device.spawn.return_value = 4321
        mgr = _manager_with_device(device)
        out = mgr.spawn("com.example.app")
        assert "pid=4321" in out
        sid = next(iter(mgr._sessions))
        assert mgr._sessions[sid].pid == 4321

    def test_run_script_loads_and_resumes_spawned(self):
        device, session = self._device_with_session()
        device.spawn.return_value = 4321
        script = MagicMock()
        session.create_script.return_value = script
        mgr = _manager_with_device(device)
        mgr.spawn("com.example.app")
        sid = next(iter(mgr._sessions))

        out = mgr.run_script(sid, "console.log('hi')")
        session.create_script.assert_called_once_with("console.log('hi')")
        script.load.assert_called_once()
        device.resume.assert_called_once_with(4321)
        assert "resumed" in out

    def test_read_messages_drains_buffer(self):
        device, session = self._device_with_session()
        script = MagicMock()
        session.create_script.return_value = script
        mgr = _manager_with_device(device)
        mgr.attach("com.example.app")
        sid = next(iter(mgr._sessions))
        mgr.run_script(sid, "send(1)")

        # Simulate frida delivering a message on its thread
        sess = mgr._sessions[sid]
        sess.on_message({"type": "send", "payload": "hello"}, None)
        sess.on_message({"type": "error", "description": "boom"}, None)

        out = mgr.read_messages(sid)
        assert "[send] hello" in out
        assert "[error] boom" in out
        # buffer drained
        assert mgr.read_messages(sid) == "(no new messages)"

    def test_message_buffer_capped(self):
        device, session = self._device_with_session()
        mgr = _manager_with_device(device)
        mgr.attach("x")
        sess = mgr._sessions[next(iter(mgr._sessions))]
        for i in range(fridamanager.MAX_BUFFERED_MESSAGES + 50):
            sess.on_message({"type": "send", "payload": i}, None)
        assert len(sess.messages) == fridamanager.MAX_BUFFERED_MESSAGES

    def test_list_sessions(self):
        device, session = self._device_with_session()
        mgr = _manager_with_device(device)
        mgr.attach("com.example.app")
        out = mgr.list_sessions()
        assert "com.example.app" in out
        assert "no-script" in out

    def test_detach_removes_session(self):
        device, session = self._device_with_session()
        mgr = _manager_with_device(device)
        mgr.attach("com.example.app")
        sid = next(iter(mgr._sessions))
        out = mgr.detach(sid)
        assert "Detached" in out
        assert sid not in mgr._sessions
        session.detach.assert_called_once()

    def test_unknown_session_raises(self):
        device, session = self._device_with_session()
        mgr = _manager_with_device(device)
        with pytest.raises(RuntimeError) as exc:
            mgr.read_messages("doesnotexist")
        assert "Unknown session_id" in str(exc.value)
