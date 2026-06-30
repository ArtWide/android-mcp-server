"""Shared helper to resolve an analysis target to a local APK file.

A "target" is either an installed package name (pulled from the device) OR a
path to a local .apk file (e.g. an uploaded dropper or a payload fetched during
analysis). This lets the static / JADX / apktool tools analyze arbitrary APK
files, not just installed apps, which is what dropper -> payload -> C2 recursion
needs.
"""

import re
from pathlib import Path


def sanitize_label(name: str) -> str:
    """Filesystem-safe key derived from a package name or file stem."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("_") or "apk"


def is_apk_file(target: str) -> bool:
    try:
        p = Path(target)
    except (OSError, ValueError):
        return False
    return p.is_file() and p.suffix.lower() == ".apk"


def resolve_apk(device_manager, target: str, workspace, include_splits: bool = False):
    """Resolve a target to (apk_path: Path, key: str).

    - If target is a path to an existing .apk file: use it directly; key is the
      sanitized file stem.
    - Otherwise treat target as an installed package name and pull it from the
      device; key is the sanitized package name.

    `key` is the per-target workspace folder name used by the JADX/apktool tools.
    """
    workspace = Path(workspace)
    if is_apk_file(target):
        p = Path(target)
        return p, sanitize_label(p.stem)

    key = sanitize_label(target)
    apks = device_manager.pull_apk(
        target, workspace / key / "apk", include_splits=include_splits)
    return apks[0], key
