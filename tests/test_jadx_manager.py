"""
Tests for JadxManager (APK pull + decompile + search/read).
External tools (jadx, java) and the ADB device are mocked.
"""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jadxmanager import JadxManager, _discover_jadx_executable


def _make_manager(tmpdir):
    device_manager = MagicMock()
    return JadxManager(device_manager, output_dir=str(tmpdir))


class TestJadxDiscovery:
    def test_jadx_path_env_file(self, tmp_path):
        fake = tmp_path / "jadx.bat"
        fake.write_text("echo jadx")
        with patch.dict(os.environ, {"JADX_PATH": str(fake)}, clear=True):
            assert _discover_jadx_executable() == str(fake)

    def test_jadx_path_env_dir_with_bin(self, tmp_path):
        bindir = tmp_path / "bin"
        bindir.mkdir()
        fake = bindir / "jadx.bat"
        fake.write_text("echo jadx")
        with patch.dict(os.environ, {"JADX_PATH": str(tmp_path)}, clear=True):
            assert _discover_jadx_executable() == str(fake)

    def test_not_found(self, tmp_path):
        with patch.dict(os.environ, {"JADX_PATH": ""}), \
                patch("jadxmanager.shutil.which", return_value=None), \
                patch("jadxmanager.Path.home", return_value=tmp_path), \
                patch("jadxmanager.Path.is_file", return_value=False):
            assert _discover_jadx_executable() is None


class TestJadxResolve:
    def test_resolve_raises_install_hint(self, tmp_path):
        mgr = _make_manager(tmp_path)
        with patch("jadxmanager._discover_jadx_executable", return_value=None):
            with pytest.raises(RuntimeError) as exc:
                mgr._resolve_jadx()
        assert "jadx executable not found" in str(exc.value)


class TestApkResolution:
    def test_apk_remote_paths_parsed(self, tmp_path):
        mgr = _make_manager(tmp_path)
        mgr.device_manager.device.shell.return_value = (
            "package:/data/app/com.x-1/base.apk\n"
            "package:/data/app/com.x-1/split_config.arm64_v8a.apk\n")
        paths = mgr._apk_remote_paths("com.x")
        assert paths == [
            "/data/app/com.x-1/base.apk",
            "/data/app/com.x-1/split_config.arm64_v8a.apk",
        ]

    def test_pull_apk_base_only(self, tmp_path):
        mgr = _make_manager(tmp_path)
        mgr.device_manager.device.shell.return_value = (
            "package:/data/app/com.x-1/split_config.arm64_v8a.apk\n"
            "package:/data/app/com.x-1/base.apk\n")
        pulled = mgr._pull_apk("com.x", include_splits=False)
        # only base.apk pulled, and it is first
        assert len(pulled) == 1
        assert pulled[0].name == "base.apk"
        mgr.device_manager.device.pull.assert_called_once()

    def test_pull_apk_missing_package(self, tmp_path):
        mgr = _make_manager(tmp_path)
        mgr.device_manager.device.shell.return_value = ""
        with pytest.raises(RuntimeError) as exc:
            mgr._pull_apk("com.missing", include_splits=False)
        assert "not found on device" in str(exc.value)


class TestDecompile:
    def test_decompile_counts_java_files(self, tmp_path):
        mgr = _make_manager(tmp_path)

        # Make pull a no-op that returns a fake apk path
        fake_apk = tmp_path / "com.x" / "apk" / "base.apk"

        def fake_pull(pkg, splits):
            fake_apk.parent.mkdir(parents=True, exist_ok=True)
            fake_apk.write_text("apk")
            return [fake_apk]

        # Simulate jadx producing two java files under src/sources
        def fake_run(cmd, **kwargs):
            src = Path(cmd[cmd.index("-d") + 1]) / "sources" / "com" / "x"
            src.mkdir(parents=True, exist_ok=True)
            (src / "A.java").write_text("class A {}")
            (src / "B.java").write_text("class B {}")
            return MagicMock(returncode=0, stdout="jadx done")

        with patch.object(mgr, "_resolve_jadx", return_value="jadx"), \
                patch.object(mgr, "_check_java"), \
                patch.object(mgr, "_pull_apk", side_effect=fake_pull), \
                patch("jadxmanager.subprocess.run", side_effect=fake_run):
            result = mgr.decompile("com.x")

        assert "Java files: 2" in result
        assert "Status: ok" in result


class TestSearchAndRead:
    def _seed_sources(self, tmp_path):
        mgr = _make_manager(tmp_path)
        src = tmp_path / "com.x" / "src" / "sources" / "com" / "x"
        src.mkdir(parents=True, exist_ok=True)
        (src / "Login.java").write_text(
            "package com.x;\nclass Login {\n  String secret = \"hunter2\";\n}\n")
        return mgr

    def test_search_finds_match(self, tmp_path):
        mgr = self._seed_sources(tmp_path)
        out = mgr.search_code("secret", "com.x")
        assert "Login.java:3" in out
        assert "hunter2" in out

    def test_search_no_match(self, tmp_path):
        mgr = self._seed_sources(tmp_path)
        out = mgr.search_code("nonexistent_token", "com.x")
        assert "No matches" in out

    def test_search_missing_package(self, tmp_path):
        mgr = _make_manager(tmp_path)
        with pytest.raises(RuntimeError) as exc:
            mgr.search_code("x", "com.absent")
        assert "No decompiled sources" in str(exc.value)

    def test_read_source_ok(self, tmp_path):
        mgr = self._seed_sources(tmp_path)
        content = mgr.read_source("com.x", "com/x/Login.java")
        assert "hunter2" in content

    def test_read_source_traversal_blocked(self, tmp_path):
        mgr = self._seed_sources(tmp_path)
        with pytest.raises(RuntimeError) as exc:
            mgr.read_source("com.x", "../../../../etc/passwd")
        assert "escapes" in str(exc.value)

    def test_list_decompiled(self, tmp_path):
        self._seed_sources(tmp_path)
        mgr = _make_manager(tmp_path)
        assert mgr.list_decompiled() == ["com.x"]
