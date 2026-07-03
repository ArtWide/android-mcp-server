"""
Tests for RepackageManager (frida-gadget repackaging).
External tools (apktool, gadget, signer) are mocked; the fragile smali/manifest
editing logic is tested directly.
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from repackagemanager import RepackageManager


def _mgr(tmp_path):
    return RepackageManager(MagicMock(), output_dir=str(tmp_path))


def _manifest(d, pkg, app_name=None):
    d.mkdir(parents=True, exist_ok=True)
    app = f' android:name="{app_name}"' if app_name is not None else ""
    (d / "AndroidManifest.xml").write_text(
        f'<manifest package="{pkg}"><application{app} android:label="x" >'
        f'</application></manifest>', encoding="utf-8")


class TestResolveApplicationClass:
    def test_relative_name(self, tmp_path):
        d = tmp_path / "dec"; _manifest(d, "com.x", ".App")
        assert RepackageManager._resolve_application_class(d) == ("com.x.App", "com.x")

    def test_absolute_name(self, tmp_path):
        d = tmp_path / "dec"; _manifest(d, "com.x", "com.y.App")
        fqcn, _ = RepackageManager._resolve_application_class(d)
        assert fqcn == "com.y.App"

    def test_bare_name(self, tmp_path):
        d = tmp_path / "dec"; _manifest(d, "com.x", "App")
        fqcn, _ = RepackageManager._resolve_application_class(d)
        assert fqcn == "com.x.App"

    def test_no_application(self, tmp_path):
        d = tmp_path / "dec"; _manifest(d, "com.x", None)
        assert RepackageManager._resolve_application_class(d) is None


class TestInjectLoadLibrary:
    def _app_smali(self, tmp_path, body):
        d = tmp_path / "dec"; _manifest(d, "com.x", ".App")
        smali = d / "smali" / "com" / "x"; smali.mkdir(parents=True)
        (smali / "App.smali").write_text(body, encoding="utf-8")
        return d, smali / "App.smali"

    def test_injects_into_existing_clinit(self, tmp_path):
        mgr = _mgr(tmp_path)
        d, f = self._app_smali(
            tmp_path,
            ".class public Lcom/x/App;\n"
            ".method static constructor <clinit>()V\n    .locals 0\n"
            "    return-void\n.end method\n")
        fqcn = mgr._inject_loadlibrary(d, "gadget")
        out = f.read_text()
        assert 'const-string v0, "gadget"' in out
        assert "loadLibrary" in out
        assert fqcn == "com.x.App"

    def test_creates_clinit_when_missing(self, tmp_path):
        mgr = _mgr(tmp_path)
        d, f = self._app_smali(
            tmp_path, ".class public Lcom/x/App;\n.super Landroid/app/Application;\n")
        mgr._inject_loadlibrary(d)
        out = f.read_text()
        assert "<clinit>()V" in out and "loadLibrary" in out

    def test_no_application_raises(self, tmp_path):
        mgr = _mgr(tmp_path)
        d = tmp_path / "dec"; _manifest(d, "com.x", None)
        with pytest.raises(RuntimeError) as exc:
            mgr._inject_loadlibrary(d)
        assert "default Application" in str(exc.value)


class TestNSC:
    def test_creates_when_absent(self, tmp_path):
        mgr = _mgr(tmp_path)
        d = tmp_path / "dec"; _manifest(d, "com.x", ".App")
        mgr._apply_nsc(d)
        assert (d / "res" / "xml" / "nsc_mitm.xml").exists()
        man = (d / "AndroidManifest.xml").read_text()
        assert 'networkSecurityConfig="@xml/nsc_mitm"' in man

    def test_merges_into_existing_preserving_cleartext(self, tmp_path):
        mgr = _mgr(tmp_path)
        d = tmp_path / "dec"; d.mkdir()
        (d / "AndroidManifest.xml").write_text(
            '<manifest package="com.x"><application '
            'android:networkSecurityConfig="@xml/net" ></application></manifest>',
            encoding="utf-8")
        xmldir = d / "res" / "xml"; xmldir.mkdir(parents=True)
        (xmldir / "net.xml").write_text(
            '<?xml version="1.0"?><network-security-config>'
            '<base-config cleartextTrafficPermitted="false">'
            '<trust-anchors><certificates src="system"/></trust-anchors>'
            '</base-config></network-security-config>', encoding="utf-8")
        note = mgr._apply_nsc(d)
        merged = (xmldir / "net.xml").read_text()
        assert 'src="user"' in merged
        assert 'cleartextTrafficPermitted="false"' in merged  # preserved
        assert "merged" in note
        assert "@xml/net" in (d / "AndroidManifest.xml").read_text()


class TestGadgetDiscovery:
    def test_bad_arch(self, tmp_path):
        mgr = _mgr(tmp_path)
        with pytest.raises(RuntimeError) as exc:
            mgr._gadget_for("mips")
        assert "Unsupported abi" in str(exc.value)

    def test_missing_gadget(self, tmp_path):
        mgr = _mgr(tmp_path)
        with patch("repackagemanager._TOOLS", tmp_path), \
                patch("repackagemanager._host_frida_version", return_value="17.15.3"), \
                patch.dict(os.environ, {"FRIDA_GADGET_SO": ""}):
            with pytest.raises(RuntimeError) as exc:
                mgr._gadget_for("arm64-v8a")
        assert "frida-gadget" in str(exc.value)

    def test_finds_versioned_gadget(self, tmp_path):
        mgr = _mgr(tmp_path)
        so = tmp_path / "frida-gadget-17.15.3-android-arm64.so"
        so.write_text("x")
        with patch("repackagemanager._TOOLS", tmp_path), \
                patch("repackagemanager._host_frida_version", return_value="17.15.3"), \
                patch.dict(os.environ, {"FRIDA_GADGET_SO": ""}):
            path, _ = mgr._gadget_for("arm64-v8a")
            assert path == str(so)

    def test_override_version_mismatch_errors(self, tmp_path):
        mgr = _mgr(tmp_path)
        so = tmp_path / "frida-gadget-16.0.0-android-arm64.so"
        so.write_text("x")
        with patch("repackagemanager._host_frida_version", return_value="17.15.3"), \
                patch.dict(os.environ, {"FRIDA_GADGET_SO": str(so)}):
            with pytest.raises(RuntimeError) as exc:
                mgr._gadget_for("arm64-v8a")
        assert "does not match host frida" in str(exc.value)
