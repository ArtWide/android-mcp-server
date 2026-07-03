"""
Tests for the AdbDeviceManager additions: pull_apk and get_logcat.
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adbdevicemanager import AdbDeviceManager


def _manager():
    with patch("adbdevicemanager.AdbDeviceManager.check_adb_installed", return_value=True), \
            patch("adbdevicemanager.AdbDeviceManager.get_available_devices", return_value=["dev1"]), \
            patch("adbdevicemanager.AdbClient", return_value=MagicMock()):
        return AdbDeviceManager(device_name="dev1", exit_on_error=False)


class TestPullApk:
    def test_base_only(self, tmp_path):
        mgr = _manager()
        mgr.device.shell.return_value = (
            "package:/data/app/com.x-1/split_config.arm64.apk\n"
            "package:/data/app/com.x-1/base.apk\n")
        pulled = mgr.pull_apk("com.x", tmp_path, include_splits=False)
        assert len(pulled) == 1
        assert pulled[0].name == "base.apk"
        mgr.device.pull.assert_called_once()

    def test_reuse_skips_pull(self, tmp_path):
        mgr = _manager()
        mgr.device.shell.return_value = "package:/data/app/com.x-1/base.apk\n"
        # pre-create the file so reuse should skip pulling
        (tmp_path / "base.apk").write_text("apk")
        pulled = mgr.pull_apk("com.x", tmp_path, reuse=True)
        assert pulled[0].name == "base.apk"
        mgr.device.pull.assert_not_called()

    def test_missing_package_raises(self, tmp_path):
        mgr = _manager()
        mgr.device.shell.return_value = ""
        with pytest.raises(RuntimeError) as exc:
            mgr.pull_apk("com.absent", tmp_path)
        assert "not found on device" in str(exc.value)


class TestFileTransfer:
    def test_push_file(self, tmp_path):
        mgr = _manager()
        f = tmp_path / "sample.apk"
        f.write_text("apk")
        out = mgr.push_file(str(f), "/data/local/tmp/sample.apk")
        mgr.device.push.assert_called_once_with(str(f), "/data/local/tmp/sample.apk")
        assert "Pushed" in out

    def test_push_missing_local(self, tmp_path):
        mgr = _manager()
        with pytest.raises(RuntimeError) as exc:
            mgr.push_file(str(tmp_path / "nope.apk"), "/data/local/tmp/x")
        assert "not found" in str(exc.value)

    def test_pull_file(self, tmp_path):
        mgr = _manager()
        dest = tmp_path / "out.bin"

        def fake_pull(remote, local):
            Path(local).write_text("data")
        mgr.device.pull.side_effect = fake_pull
        out = mgr.pull_file("/sdcard/x.bin", str(dest))
        assert dest.exists()
        assert "Pulled" in out

    def test_install_apk(self, tmp_path):
        mgr = _manager()
        f = tmp_path / "m.apk"
        f.write_text("apk")
        out = mgr.install_apk(str(f), reinstall=True, grant_permissions=True)
        mgr.device.install.assert_called_once()
        _, kwargs = mgr.device.install.call_args
        assert kwargs["reinstall"] is True
        assert kwargs["grand_all_permissions"] is True
        assert "Installed" in out

    def test_install_missing_apk(self, tmp_path):
        mgr = _manager()
        with pytest.raises(RuntimeError) as exc:
            mgr.install_apk(str(tmp_path / "nope.apk"))
        assert "not found" in str(exc.value)


class TestInstallAndLaunch:
    def test_uninstall_install_launch(self, tmp_path):
        mgr = _manager()
        f = tmp_path / "r.apk"; f.write_text("apk")
        mgr.device.shell.return_value = "ok"
        out = mgr.install_and_launch(str(f), package="com.x", launch=True)
        mgr.device.uninstall.assert_called_once_with("com.x")
        mgr.device.install.assert_called_once()
        assert "installed" in out and "undo" in out

    def test_install_error_returned_raw(self, tmp_path):
        mgr = _manager()
        f = tmp_path / "r.apk"; f.write_text("apk")
        mgr.device.install.side_effect = Exception("INSTALL_FAILED_UPDATE_INCOMPATIBLE")
        out = mgr.install_and_launch(str(f), package="com.x")
        assert "INSTALL FAILED" in out and "INSTALL_FAILED_UPDATE_INCOMPATIBLE" in out


class TestInstallUserCa:
    def test_local_cert(self, tmp_path):
        mgr = _manager()
        cert = tmp_path / "ca.cer"; cert.write_text("PEM")
        out = mgr.install_user_ca(str(cert))
        mgr.device.push.assert_called_once()
        mgr.device.shell.assert_any_call(
            "am start -a android.settings.SECURITY_SETTINGS")
        assert "Undo" in out

    def test_missing_local_cert(self, tmp_path):
        mgr = _manager()
        with pytest.raises(RuntimeError) as exc:
            mgr.install_user_ca(str(tmp_path / "nope.cer"))
        assert "not found" in str(exc.value)


class TestDeviceSelection:
    @patch("adbdevicemanager.AdbClient")
    @patch.object(AdbDeviceManager, "get_available_devices")
    def test_list_devices_marks_active(self, mock_get, mock_client):
        mgr = _manager()
        mgr.device.serial = "dev1"
        mock_get.return_value = ["dev1", "dev2"]
        mock_client.return_value.device.return_value.shell.return_value = "Pixel"
        out = mgr.list_devices()
        assert "dev1" in out and "dev2" in out
        assert "<- active" in out

    @patch("adbdevicemanager.AdbClient")
    @patch.object(AdbDeviceManager, "get_available_devices")
    def test_select_device_switches(self, mock_get, mock_client):
        mgr = _manager()
        mock_get.return_value = ["dev1", "dev2"]
        new_dev = MagicMock()
        mock_client.return_value.device.return_value = new_dev
        out = mgr.select_device("dev2")
        assert mgr.device == new_dev
        assert "dev2" in out

    @patch.object(AdbDeviceManager, "get_available_devices")
    def test_select_device_not_found(self, mock_get):
        mgr = _manager()
        mock_get.return_value = ["dev1"]
        with pytest.raises(RuntimeError) as exc:
            mgr.select_device("devX")
        assert "not found" in str(exc.value)

    def test_get_current_device(self):
        mgr = _manager()
        mgr.device.serial = "dev1"
        mgr.device.shell.return_value = "Pixel 5"
        out = mgr.get_current_device()
        assert "dev1" in out and "Pixel 5" in out


class TestLogcat:
    def test_builds_command(self):
        mgr = _manager()
        mgr.device.shell.return_value = "log output"
        out = mgr.get_logcat(lines=50, priority="E")
        assert out == "log output"
        called = mgr.device.shell.call_args[0][0]
        assert "logcat -d -t 50" in called
        assert "*:E" in called

    def test_filter_spec(self):
        mgr = _manager()
        mgr.device.shell.return_value = "x"
        mgr.get_logcat(filter_spec="ActivityManager:I *:S")
        called = mgr.device.shell.call_args[0][0]
        assert "ActivityManager:I *:S" in called
