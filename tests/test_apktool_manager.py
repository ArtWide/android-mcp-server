"""
Tests for ApktoolManager. External apktool/java and the device are mocked.
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apktoolmanager import ApktoolManager, _discover_apktool


def _mgr(tmp_path):
    dm = MagicMock()
    return ApktoolManager(dm, output_dir=str(tmp_path))


class TestDiscovery:
    def test_env_file(self, tmp_path):
        fake = tmp_path / "apktool.bat"
        fake.write_text("x")
        with patch.dict(os.environ, {"APKTOOL_PATH": str(fake)}):
            assert _discover_apktool() == str(fake)

    def test_resolve_raises_hint(self, tmp_path):
        mgr = _mgr(tmp_path)
        with patch("apktoolmanager._discover_apktool", return_value=None):
            with pytest.raises(RuntimeError) as exc:
                mgr._resolve()
        assert "apktool executable not found" in str(exc.value)


class TestDecode:
    def test_decode_summary(self, tmp_path):
        mgr = _mgr(tmp_path)
        fake_apk = tmp_path / "com.x" / "apk" / "base.apk"

        def fake_pull(pkg, dest, include_splits=False):
            fake_apk.parent.mkdir(parents=True, exist_ok=True)
            fake_apk.write_text("apk")
            return [fake_apk]
        mgr.device_manager.pull_apk.side_effect = fake_pull

        def fake_run(cmd, **kwargs):
            out = Path(cmd[cmd.index("-o") + 1])
            (out / "smali").mkdir(parents=True, exist_ok=True)
            (out / "res").mkdir(parents=True, exist_ok=True)
            (out / "AndroidManifest.xml").write_text("<manifest/>")
            return MagicMock(returncode=0, stdout="I: done")

        with patch.object(mgr, "_resolve", return_value="apktool"), \
                patch.object(mgr, "_check_java"), \
                patch("apktoolmanager.subprocess.run", side_effect=fake_run):
            out = mgr.decode("com.x")
        assert "Status: ok" in out
        assert "AndroidManifest.xml: True" in out


class TestListRead:
    def _seed(self, tmp_path):
        mgr = _mgr(tmp_path)
        root = tmp_path / "com.x" / "apktool"
        (root / "smali").mkdir(parents=True, exist_ok=True)
        (root / "AndroidManifest.xml").write_text("<manifest package='com.x'/>")
        (root / "smali" / "A.smali").write_text(".class public LA;")
        return mgr

    def test_list_files(self, tmp_path):
        mgr = self._seed(tmp_path)
        out = mgr.list_files("com.x")
        assert "AndroidManifest.xml" in out
        assert "smali/" in out

    def test_read_manifest(self, tmp_path):
        mgr = self._seed(tmp_path)
        assert "package='com.x'" in mgr.read_file("com.x", "AndroidManifest.xml")

    def test_read_traversal_blocked(self, tmp_path):
        mgr = self._seed(tmp_path)
        with pytest.raises(RuntimeError) as exc:
            mgr.read_file("com.x", "../../../../etc/passwd")
        assert "escapes" in str(exc.value)

    def test_list_before_decode_raises(self, tmp_path):
        mgr = _mgr(tmp_path)
        with pytest.raises(RuntimeError) as exc:
            mgr.list_files("com.absent")
        assert "not decoded yet" in str(exc.value)
