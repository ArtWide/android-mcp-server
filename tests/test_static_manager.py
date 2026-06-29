"""
Tests for StaticAnalysisManager. androguard's APK object is mocked, so these
run without a real APK or device.
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from staticmanager import StaticAnalysisManager


def _mgr(tmp_path):
    return StaticAnalysisManager(MagicMock(), output_dir=str(tmp_path))


class TestScanSecrets:
    def test_categorizes_matches(self, tmp_path):
        mgr = _mgr(tmp_path)
        strings = {
            "AIzaSyA1234567890abcdefghijklmnopqrstuvw",  # Google API key (39 chars after AIza? pattern needs 35)
            "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
            "https://api.example.com/v1/login",
            "http://10.0.0.1/health",
            "10.0.0.1",
            "just a normal string",
            "eyJabcdefgh.eyJpayload1.signature99",
        }
        with patch.object(mgr, "_load", return_value=MagicMock()), \
                patch.object(mgr, "_dex_strings", return_value=strings):
            out = mgr.scan_secrets("com.x")
        assert "URL" in out
        assert "https://api.example.com/v1/login" in out
        assert "IPv4 address" in out
        assert "Scanned 7 dex strings" in out

    def test_no_matches(self, tmp_path):
        mgr = _mgr(tmp_path)
        with patch.object(mgr, "_load", return_value=MagicMock()), \
                patch.object(mgr, "_dex_strings", return_value={"hello", "world"}):
            out = mgr.scan_secrets("com.x")
        assert "No matches" in out


class TestExportedComponents:
    def test_explicit_and_implicit(self, tmp_path):
        mgr = _mgr(tmp_path)
        apk = MagicMock()

        def attr(kind, name_attr, name=None):
            return "true" if name == "A" else None
        apk.get_attribute_value.side_effect = attr
        # B has an intent filter, C has neither
        apk.get_intent_filters.side_effect = lambda kind, n: ["filter"] if n == "B" else []

        result = mgr._exported_components(apk, "activity", ["A", "B", "C"])
        joined = "\n".join(result)
        assert "A" in joined and "exported=true" in joined
        assert "B" in joined and "intent-filter" in joined
        assert "C" not in joined


class TestAnalyzeManifest:
    def test_smoke(self, tmp_path):
        mgr = _mgr(tmp_path)
        apk = MagicMock()
        apk.get_package.return_value = "com.x"
        apk.get_androidversion_name.return_value = "1.0"
        apk.get_androidversion_code.return_value = "1"
        apk.get_min_sdk_version.return_value = "21"
        apk.get_target_sdk_version.return_value = "33"
        apk.get_max_sdk_version.return_value = None
        apk.get_main_activity.return_value = "com.x.Main"
        apk.get_permissions.return_value = ["android.permission.CAMERA", "android.permission.INTERNET"]
        apk.get_activities.return_value = ["com.x.Main"]
        apk.get_services.return_value = []
        apk.get_receivers.return_value = []
        apk.get_providers.return_value = []
        apk.get_attribute_value.return_value = None
        apk.get_intent_filters.return_value = []

        with patch.object(mgr, "_load", return_value=apk):
            out = mgr.analyze_manifest("com.x")
        assert "Package: com.x" in out
        assert "android.permission.CAMERA" in out
        assert "Dangerous-permission highlights" in out  # CAMERA is dangerous
