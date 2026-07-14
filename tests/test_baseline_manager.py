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
        import re
        m = re.match(r"""su -c ['"](.*)['"]\s*$""", cmd, re.S)
        inner = m.group(1) if m else cmd
        # --- state-mutating commands (restore_baseline) ---
        if inner.startswith("pm uninstall "):
            pkg = inner.split()[-1]
            s["packages"] = [p for p in s["packages"] if p != pkg]
            s["third_party"].pop(pkg, None)
            return "Success"
        if inner.startswith("dpm remove-active-admin "):
            comp = inner.split()[-1]
            s["admins"] = [c for c in s.get("admins", []) if c != comp]
            return "Success: Admin " + comp + " removed"
        if inner.startswith("rm -f "):
            path = inner[len("rm -f "):].strip().strip("'\"")
            for d, lst in s.get("files", {}).items():
                s["files"][d] = [f for f in lst if f != path]
            return ""
        if inner.startswith("settings put "):
            p = inner[len("settings put "):].split(None, 2)
            s.setdefault("settings", {})[f"{p[0]}/{p[1]}"] = (
                p[2].strip().strip("'\"") if len(p) > 2 else "")
            return ""
        if inner.startswith("settings delete "):
            p = inner[len("settings delete "):].split()
            s.get("settings", {}).pop(f"{p[0]}/{p[1]}", None)
            return ""
        # --- read commands ---
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


def _clean_pre():
    return {
        "packages": ["com.android.chrome"],
        "third_party": {},
        "processes": ["system_server"],
        "tcp": [],
        "admins": [],
        "settings": {"secure/sms_default_application": "com.android.messaging"},
        "files": {"/data/local/tmp": [], "/sdcard/Download": [],
                  "/sdcard/Android/data": []},
    }


def _dirty_post():
    # after installing/running the sample: +2 packages, +admin, sms hijacked, +file
    return {
        "packages": ["com.android.chrome", "com.sample", "com.evil.payload"],
        "third_party": {"com.sample": "/data/app/com.sample/base.apk",
                        "com.evil.payload": "/data/app/com.evil.payload/base.apk"},
        "processes": ["system_server", "com.sample"],
        "tcp": [("0100007F:ABCD", "04030201:01BB", "01")],
        "admins": ["com.evil.payload/.AdminRx"],
        "settings": {"secure/sms_default_application": "com.evil.payload"},
        "files": {"/data/local/tmp": ["/data/local/tmp/stage2.dex"],
                  "/sdcard/Download": [], "/sdcard/Android/data": []},
    }


class TestRestore:
    def _setup(self, tmp_path, serial="devA"):
        mgr = _manager(tmp_path, serial, _clean_pre())
        mgr.capture_baseline("pre")
        mgr.dm.device.state = _dirty_post()
        mgr.capture_baseline("post")
        return mgr

    def test_dry_run_reports_plan_without_changing(self, tmp_path):
        mgr = self._setup(tmp_path)
        out = mgr.restore_baseline("pre", "post", apply=False)
        assert "dry run" in out
        assert "com.sample" in out and "com.evil.payload" in out   # uninstall plan
        assert "com.evil.payload/.AdminRx" in out                  # admin plan
        # nothing removed
        assert "com.evil.payload" in mgr.dm.device.state["packages"]

    def test_apply_removes_and_verifies_restored(self, tmp_path):
        mgr = self._setup(tmp_path)
        out = mgr.restore_baseline("pre", "post", apply=True)
        st = mgr.dm.device.state
        assert st["packages"] == ["com.android.chrome"]           # sample+payload gone
        assert st["admins"] == []                                  # admin disabled
        assert st["settings"]["secure/sms_default_application"] == "com.android.messaging"
        assert st["files"]["/data/local/tmp"] == []                # dropped file gone
        assert "RESTORED" in out and "matches baseline" in out

    def test_device_mismatch_raises(self, tmp_path):
        mgr = self._setup(tmp_path)
        pre = str(tmp_path / "baseline" / "devA_pre.json")
        post = str(tmp_path / "baseline" / "devA_post.json")
        mgr.dm.device = FakeDevice("devB", _dirty_post())          # switch active device
        with pytest.raises(RuntimeError) as exc:
            mgr.restore_baseline(pre, post, apply=True)
        assert "different device" in str(exc.value) or "active device" in str(exc.value)

    def test_stale_session_warns(self, tmp_path):
        import json
        mgr = self._setup(tmp_path)
        pre_path = tmp_path / "baseline" / "devA_pre.json"
        snap = json.loads(pre_path.read_text(encoding="utf-8"))
        snap["session_id"] = "OLD-SESSION"
        pre_path.write_text(json.dumps(snap), encoding="utf-8")
        out = mgr.restore_baseline("pre", "post", apply=False)
        assert "earlier server session" in out
