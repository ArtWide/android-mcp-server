#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pin the host frida binding to the version the analysis device needs, BEFORE
server.py imports frida.

Why a separate pre-launch step: frida's host bindings and the device
frida-server must be the *same* version, and the `frida` module is loaded at
import time inside the long-lived server process -- it cannot be swapped live.
So `scripts/3-run_server.ps1` runs THIS short-lived process first; it reinstalls
`frida` into the venv if needed and exits, then the server starts fresh and
imports the aligned version. No server restart is required.

Target version resolution (first hit wins):
  1. env FRIDA_VERSION
  2. config.yaml -> frida.version
  3. the connected device's `frida-server --version` (read over adb)

It is a no-op when the target can't be determined or already matches. It is
strictly best-effort: any failure leaves the current frida in place (the MCP
tool `frida_check_compatibility` will still surface a mismatch), and it never
raises so it cannot block server startup.

Note: this reads the *installed* frida version via importlib.metadata, which
does NOT import the frida module -- so this process never loads frida, and the
reinstall it performs is picked up cleanly by the server process that follows.
"""
import os
import shutil
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, version

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SERVER_PATH = "/data/local/tmp/frida-server"


def _log(msg):
    print(f"[frida-align] {msg}")


def _config():
    try:
        import yaml
        path = os.path.join(REPO, "config.yaml")
        if not os.path.exists(path):
            return {}
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _configured_version(cfg):
    v = (cfg.get("frida") or {}).get("version")
    return str(v).strip() if v else None


def _device_version(cfg):
    """Read the device frida-server --version over adb (independent of host frida)."""
    adb = shutil.which("adb")
    if not adb:
        return None
    server_path = (cfg.get("frida") or {}).get("server_path") \
        or os.environ.get("FRIDA_SERVER_PATH") or DEFAULT_SERVER_PATH
    try:
        out = subprocess.run([adb, "devices"], capture_output=True, text=True,
                             timeout=10).stdout
        serials = [ln.split("\t")[0] for ln in out.splitlines() if "\tdevice" in ln]
        if not serials:
            return None
        r = subprocess.run([adb, "-s", serials[0], "shell",
                            f"{server_path} --version 2>/dev/null"],
                           capture_output=True, text=True, timeout=15)
        v = (r.stdout or "").strip()
        return v or None
    except Exception:
        return None


def _installed_version():
    try:
        return version("frida")
    except PackageNotFoundError:
        return None
    except Exception:
        return None


def _find_uv():
    u = shutil.which("uv")
    if u:
        return u
    for c in (os.path.expanduser(r"~\.android-mcp-tools\uv\uv.exe"),
              os.path.expanduser(r"~\.local\bin\uv.exe"),
              os.path.expanduser("~/.local/bin/uv")):
        if os.path.exists(c):
            return c
    return None


def _install(target):
    """Install frida==target into THIS interpreter's venv. Try uv first, then
    pip; fall back to --no-deps so a frida-tools pin can't block a downgrade
    (the MCP uses the `frida` module, not the frida-tools CLI, at runtime)."""
    uv = _find_uv()
    spec = f"frida=={target}"
    attempts = []
    if uv:
        attempts.append([uv, "pip", "install", "--python", sys.executable, spec])
        attempts.append([uv, "pip", "install", "--python", sys.executable, "--no-deps", spec])
    attempts.append([sys.executable, "-m", "pip", "install", spec])
    attempts.append([sys.executable, "-m", "pip", "install", "--no-deps", spec])
    last = None
    for cmd in attempts:
        try:
            subprocess.run(cmd, check=True, timeout=600)
            return True
        except Exception as e:
            last = e
    _log(f"install failed ({last}); keeping the current frida.")
    return False


def main(dry_run=False):
    cfg = _config()
    source = "env FRIDA_VERSION"
    target = os.environ.get("FRIDA_VERSION")
    if not target:
        target = _configured_version(cfg); source = "config.yaml frida.version"
    if not target:
        target = _device_version(cfg); source = "device frida-server"
    if not target:
        _log("no target version (no env / config / device) -> leaving frida as-is.")
        return

    installed = _installed_version()
    if installed == target:
        _log(f"host frida already {target} (via {source}) -> ok.")
        return

    if dry_run:
        _log(f"[dry-run] would align host frida {installed or 'NONE'} -> {target} "
             f"(via {source}). No changes made.")
        return

    _log(f"aligning host frida {installed or 'NONE'} -> {target} (via {source}) ...")
    if _install(target):
        _log(f"done: frida=={target}. Server will load the matching version.")


if __name__ == "__main__":
    _dry = "--dry-run" in sys.argv[1:] or "--check" in sys.argv[1:]
    try:
        main(dry_run=_dry)
    except Exception as e:  # never block server startup
        _log(f"skipped due to error: {e}")
