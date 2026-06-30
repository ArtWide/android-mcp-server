"""
Tests for apkutils.resolve_apk (target = installed package OR .apk file path).
"""

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apkutils import resolve_apk, is_apk_file, sanitize_label


def test_sanitize_label():
    assert sanitize_label("com.example.app") == "com.example.app"
    assert sanitize_label("a/b:c*d") == "a_b_c_d"


def test_file_target_used_directly(tmp_path):
    f = tmp_path / "payload.apk"
    f.write_text("apk")
    dm = MagicMock()
    apk_path, key = resolve_apk(dm, str(f), tmp_path)
    assert apk_path == f
    assert key == "payload"
    dm.pull_apk.assert_not_called()


def test_package_target_pulls_from_device(tmp_path):
    dm = MagicMock()
    dm.pull_apk.return_value = [tmp_path / "base.apk"]
    apk_path, key = resolve_apk(dm, "com.x.app", tmp_path)
    assert key == "com.x.app"
    assert apk_path.name == "base.apk"
    dm.pull_apk.assert_called_once()


def test_is_apk_file(tmp_path):
    f = tmp_path / "a.apk"
    f.write_text("x")
    assert is_apk_file(str(f)) is True
    assert is_apk_file("com.example.app") is False
    assert is_apk_file(str(tmp_path / "missing.apk")) is False
