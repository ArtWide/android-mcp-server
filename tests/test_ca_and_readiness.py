"""Tests for system-CA install, CA trust status, and the dynamic readiness check."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adbdevicemanager import AdbDeviceManager
from readiness import dynamic_readiness

# A tiny real self-signed cert so _ca_hash_filename can parse it.
_TEST_CERT = None


def _make_cert(tmp_path):
    """Generate a throwaway PEM CA to exercise hash computation."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mitmproxy-test")])
    epoch = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(epoch).not_valid_after(epoch + timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    p = tmp_path / "ca.cer"
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return p


def _manager():
    with patch("adbdevicemanager.AdbDeviceManager.check_adb_installed", return_value=True), \
            patch("adbdevicemanager.AdbDeviceManager.get_available_devices", return_value=["dev1"]), \
            patch("adbdevicemanager.AdbClient", return_value=MagicMock()):
        return AdbDeviceManager(device_name="dev1", exit_on_error=False)


class TestCaHash:
    def test_hash_filename_format(self, tmp_path):
        cert = _make_cert(tmp_path)
        fname = AdbDeviceManager._ca_hash_filename(cert)
        assert fname.endswith(".0")
        assert len(fname) == 10  # 8 hex + '.0'
        int(fname[:8], 16)  # parses as hex


class TestIsRooted:
    def test_rooted(self):
        mgr = _manager()
        mgr.device.shell.return_value = "uid=0(root) gid=0(root)"
        assert mgr.is_rooted() is True

    def test_not_rooted(self):
        mgr = _manager()
        mgr.device.shell.return_value = "/system/bin/sh: su: not found"
        assert mgr.is_rooted() is False


class TestInstallSystemCa:
    def test_requires_root(self, tmp_path):
        mgr = _manager()
        mgr.device.shell.return_value = "su: not found"  # is_rooted() -> False
        with pytest.raises(RuntimeError) as exc:
            mgr.install_system_ca(str(_make_cert(tmp_path)))
        assert "not rooted" in str(exc.value)

    def test_success_reports_undo_and_log(self, tmp_path):
        mgr = _manager()
        cert = _make_cert(tmp_path)
        fname = AdbDeviceManager._ca_hash_filename(cert)

        def shell(cmd):
            if cmd.startswith("su -c id"):
                return "uid=0(root)"
            if "getprop ro.build.version.sdk" in cmd:
                return "33\n"
            if cmd.startswith("su -c '") and "mount -t tmpfs" in cmd:
                return "INSTALLED count=160"
            if f"ls /system/etc/security/cacerts/{fname}" in cmd:
                return f"/system/etc/security/cacerts/{fname}"
            return ""

        mgr.device.shell.side_effect = shell
        out = mgr.install_system_ca(str(cert))
        assert "OK" in out
        assert "undo:" in out and "umount" in out
        assert fname in out
        mgr.device.push.assert_called_once()

    def test_android14_warns_about_apex(self, tmp_path):
        mgr = _manager()
        cert = _make_cert(tmp_path)
        fname = AdbDeviceManager._ca_hash_filename(cert)

        def shell(cmd):
            if cmd.startswith("su -c id"):
                return "uid=0(root)"
            if "getprop ro.build.version.sdk" in cmd:
                return "34\n"
            if "mount -t tmpfs" in cmd:
                return "INSTALLED count=160"
            if f"ls /system/etc/security/cacerts/{fname}" in cmd:
                return f"/system/etc/security/cacerts/{fname}"
            return ""

        mgr.device.shell.side_effect = shell
        out = mgr.install_system_ca(str(cert))
        assert "APEX" in out and "ssl-unpin" in out


class TestReadiness:
    def _managers(self, rooted=True):
        dm = MagicMock()
        dm.device.serial = "dev1"
        dm.device.shell.return_value = "x"
        dm.is_rooted.return_value = rooted
        dm.ca_trust_status.return_value = {
            "filename": "abcd1234.0", "in_system": rooted,
            "in_user": False, "rooted": rooted}
        frida = MagicMock()
        frida.check_compatibility.return_value = "[OK] frida versions match"
        net = MagicMock()
        net.status.return_value = "not running"
        repack = MagicMock()
        repack.check_toolchain.return_value = "[OK] apktool present"
        return dm, frida, net, repack

    def test_sections_present(self):
        dm, frida, net, repack = self._managers(rooted=True)
        with patch("readiness.Path") as PathMock:
            # host CA "exists"
            PathMock.home.return_value.__truediv__.return_value.__truediv__.return_value.is_file.return_value = True
            out = dynamic_readiness(dm, frida, net, repack)
        assert "[device]" in out
        assert "[frida]" in out
        assert "[network / mitmproxy]" in out
        assert "[HTTPS trust (device)]" in out
        assert "[repackage toolchain (non-root fallback)]" in out
        assert "frida versions match" in out

    def test_not_rooted_hint(self):
        dm, frida, net, repack = self._managers(rooted=False)
        out = dynamic_readiness(dm, frida, net, repack)
        assert "root:" in out
        assert "NOT available" in out
