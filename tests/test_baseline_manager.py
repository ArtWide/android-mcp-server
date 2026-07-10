"""Tests for BaselineManager: capture, snapshot persistence, and diff."""

import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from baselinemanager import BaselineManager, _hex_to_ip_port


def _tcp(rows):
    """Build a /proc/net/tcp-style blob from (local, remote, state_hex) rows."""
    header = "  sl  local_address rem_address   st ...\n"
    body = "".join(
        f"   {i}: {loc} {rem} {st} 0 0 0\n"
        for i, (loc, rem, st) in enumerate(rows))
    return header + body


class FakeDevice:
    """A device.shell that answers baseline queries from a state dict."""

    def __init__(self, serial, state):
        self.serial = serial
        self.state = state

    def shell(self, cmd, timeout=None):
        s = self.state
        if cmd == "pm list packages":
            return "".join(f"package:{p}\n" for p in s["packages"])
        if cmd == "pm list packages -f -3":
            return "".join(
                f"package:{path}={pkg}\n" for pkg, path in s["third_party"].items())
        if cmd == "ps -A":
            return "USER PID NAME\n" + "".join(
                f"root {1000 + i} {n}\n" for i, n in enumerate(s["processes"]))
        if cmd.startswith("cat /proc/net/tcp "):
            return _tcp(s.get("tcp", []))
        if cmd.startswith("cat /proc/net/"):  # tcp6/udp/udp6 empty
            return "  sl  local_address\n"
        if cmd == "dumpsys device_policy":
            return "\n".join(
                f"  Admin ComponentInfo{{{c}}}" for c in s.get("admins", []))
        if cmd.startswith("settings get "):
            key = cmd[len("settings get "):].strip().replace(" ", "/")
            return s.get("settings", {}).get(key, "null")
        if cmd == "date":
            return s.get("date", "Tue Jan 1 00:00:00 2026")
        if cmd.startswith("find "):
            d = cmd.split()[1]
            return "\n".join(s.get("files", {}).get(d, []))
        if cmd.startswith("stat -c %s "):
            return "123"
        return ""


def _manager(tmp_path, serial, state):
    dm = MagicMock()
    dm.device = FakeDevice(serial, state)
    return BaselineManager(dm, output_dir=tmp_path)


def _pre_state():
    return {
        "packages": ["com.android.chrome", "com.dropper.app"],
        "third_party": {"com.dropper.app": "/data/app/com.dropper.app/base.apk"},
        "processes": ["system_server", "com.dropper.app"],
        "tcp": [("0100007F:0000", "00000000:0000", "0A")],  # local listener
        "admins": [],
        "settings": {"secure/sms_default_application": "com.android.messaging"},
        "files": {"/data/local/tmp": [], "/sdcard/Download": [],
                  "/sdcard/Android/data": []},
    }


class TestHexConversion:
    def test_ipv4(self):
        # 1.2.3.4:443 little-endian -> 04030201:01BB
        assert _hex_to_ip_port("04030201:01BB") == "1.2.3.4:443"

    def test_zero(self):
        assert _hex_to_ip_port("00000000:0000") == "0.0.0.0:0"


class TestCapture:
    def test_writes_snapshot_and_summary(self, tmp_path):
        mgr = _manager(tmp_path, "devA", _pre_state())
        out = mgr.capture_baseline("pre")
        snap = tmp_path / "baseline" / "devA_pre.json"
        assert snap.is_file()
        assert "packages: 2 (1 third-party)" in out
        assert "Baseline 'pre' captured for devA" in out

    def test_serial_sanitized_in_filename(self, tmp_path):
        mgr = _manager(tmp_path, "192.168.0.2:5555", _pre_state())
        mgr.capture_baseline("pre")
        # ':' and '.' -> the path must still resolve
        files = list((tmp_path / "baseline").glob("*_pre.json"))
        assert len(files) == 1


class TestDiff:
    def test_detects_dropped_payload_and_c2(self, tmp_path):
        pre = _pre_state()
        post = _pre_state()
        # payload installed + a new C2 connection + new device admin + setting change + file
        post["packages"] = post["packages"] + ["com.evil.payload"]
        post["third_party"]["com.evil.payload"] = "/data/app/com.evil.payload/base.apk"
        post["tcp"] = post["tcp"] + [("0100007F:ABCD", "04030201:01BB", "01")]
        post["admins"] = ["com.evil.payload/.AdminRx"]
        post["settings"]["secure/sms_default_application"] = "com.evil.payload"
        post["files"]["/data/local/tmp"] = ["/data/local/tmp/stage2.dex"]

        mgr = _manager(tmp_path, "devA", pre)
        mgr.capture_baseline("pre")
        mgr.dm.device.state = post
        mgr.capture_baseline("post")
        diff = mgr.diff_baseline("pre", "post")

        assert "com.evil.payload" in diff
        assert "NEW PACKAGES" in diff
        assert "1.2.3.4:443" in diff and "C2 candidates" in diff
        assert "NEW DEVICE ADMINS" in diff
        assert "sms_default_application" in diff
        assert "stage2.dex" in diff

    def test_no_changes(self, tmp_path):
        mgr = _manager(tmp_path, "devA", _pre_state())
        mgr.capture_baseline("pre")
        mgr.capture_baseline("post")
        diff = mgr.diff_baseline("pre", "post")
        assert "no observable changes" in diff

    def test_missing_snapshot_raises(self, tmp_path):
        mgr = _manager(tmp_path, "devA", _pre_state())
        mgr.capture_baseline("pre")
        with pytest.raises(RuntimeError) as exc:
            mgr.diff_baseline("pre", "nope")
        assert "not found" in str(exc.value)
