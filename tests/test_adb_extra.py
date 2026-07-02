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
