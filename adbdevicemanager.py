import os
import shutil
import subprocess
import sys
from pathlib import Path

from PIL import Image as PILImage
from ppadb.client import Client as AdbClient

# Store screenshots next to this file regardless of CWD
_HERE = Path(__file__).parent
SCREENSHOT_PATH = str(_HERE / "screenshot.png")
COMPRESSED_PATH = str(_HERE / "compressed_screenshot.png")


def _discover_adb_executable() -> str | None:
    adb_path = os.environ.get("ADB_PATH", "").strip()
    if adb_path:
        adb_candidate = Path(adb_path)
        if adb_candidate.is_file():
            return str(adb_candidate)
        if adb_candidate.is_dir():
            candidate = adb_candidate / "adb.exe"
            if candidate.is_file():
                return str(candidate)

    which_adb = shutil.which("adb")
    if which_adb:
        return which_adb

    common_locations = [
        Path.home() / "platform-tools" / "adb.exe",
        Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "platform-tools" / "adb.exe",
        Path("C:/platform-tools/adb.exe"),
        Path("C:/Users/user/platform-tools/adb.exe"),
    ]
    for candidate in common_locations:
        if candidate.is_file():
            return str(candidate)

    return None


def _ensure_adb_on_path() -> None:
    adb_executable = _discover_adb_executable()
    if not adb_executable:
        return

    adb_directory = str(Path(adb_executable).parent)
    current_path = os.environ.get("PATH", "")
    path_parts = current_path.split(os.pathsep) if current_path else []
    if adb_directory not in path_parts:
        os.environ["PATH"] = adb_directory + os.pathsep + current_path if current_path else adb_directory


_ensure_adb_on_path()


class AdbDeviceManager:
    def __init__(self, device_name: str | None = None, exit_on_error: bool = True) -> None:
        """
        Initialize the ADB Device Manager

        Args:
            device_name: Optional name/serial of the device to manage.
                         If None, attempts to auto-select if only one device is available.
            exit_on_error: Whether to exit the program if device initialization fails
        """
        if not self.check_adb_installed():
            error_msg = "adb is not installed or not in PATH. Please install adb and ensure it is in your PATH."
            if exit_on_error:
                print(error_msg, file=sys.stderr)
                sys.exit(1)
            else:
                raise RuntimeError(error_msg)

        available_devices = self.get_available_devices()
        if not available_devices:
            error_msg = "No devices connected. Please connect a device and try again."
            if exit_on_error:
                print(error_msg, file=sys.stderr)
                sys.exit(1)
            else:
                raise RuntimeError(error_msg)

        selected_device_name: str | None = None

        if device_name:
            if device_name not in available_devices:
                error_msg = f"Device {device_name} not found. Available devices: {available_devices}"
                if exit_on_error:
                    print(error_msg, file=sys.stderr)
                    sys.exit(1)
                else:
                    raise RuntimeError(error_msg)
            selected_device_name = device_name
        else:  # No device_name provided, try auto-selection
            if len(available_devices) == 1:
                selected_device_name = available_devices[0]
                print(
                    f"No device specified, automatically selected: {selected_device_name}")
            elif len(available_devices) > 1:
                # Multiple devices and no device specified: auto-select the
                # first one (rather than failing) and say so. Set device.name in
                # config.yaml to pick a specific device.
                selected_device_name = available_devices[0]
                print(
                    f"Multiple devices connected: {available_devices}. "
                    f"Auto-selecting the first ({selected_device_name}). "
                    f"To choose a specific device, set device.name in config.yaml.")
            # If len(available_devices) == 0, it's already caught by the earlier check

        # At this point, selected_device_name should always be set due to the logic above
        # Initialize the device
        self.device = AdbClient().device(selected_device_name)

    @staticmethod
    def check_adb_installed() -> bool:
        """Check if ADB is installed on the system."""
        try:
            subprocess.run(["adb", "version"], check=True, stdout=subprocess.PIPE)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    @staticmethod
    def get_available_devices() -> list[str]:
        """Get a list of available devices."""
        return [device.serial for device in AdbClient().devices()]

    def get_packages(self) -> str:
        command = "pm list packages"
        packages = self.device.shell(command).strip().split("\n")
        result = [package[8:] for package in packages]
        output = "\n".join(result)
        return output

    def get_package_action_intents(self, package_name: str) -> list[str]:
        command = f"dumpsys package {package_name}"
        output = self.device.shell(command)

        resolver_table_start = output.find("Activity Resolver Table:")
        if resolver_table_start == -1:
            return []
        resolver_section = output[resolver_table_start:]

        non_data_start = resolver_section.find("\n  Non-Data Actions:")
        if non_data_start == -1:
            return []

        section_end = resolver_section[non_data_start:].find("\n\n")
        if section_end == -1:
            non_data_section = resolver_section[non_data_start:]
        else:
            non_data_section = resolver_section[
                non_data_start: non_data_start + section_end
            ]

        actions = []
        for line in non_data_section.split("\n"):
            line = line.strip()
            if line.startswith("android.") or line.startswith("com."):
                actions.append(line)

        return actions

    def execute_adb_shell_command(self, command: str) -> str:
        """Executes an ADB command and returns the output."""
        if command.startswith("adb shell "):
            command = command[10:]
        elif command.startswith("adb "):
            command = command[4:]
        result = self.device.shell(command)
        return result

    def apk_remote_paths(self, package_name: str) -> list[str]:
        """Return the on-device APK path(s) for a package via `pm path`."""
        output = self.device.shell(f"pm path {package_name}")
        paths = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                paths.append(line[len("package:"):])
        return paths

    def pull_apk(self, package_name: str, dest_dir, include_splits: bool = False,
                 reuse: bool = True) -> list:
        """Pull a package's APK(s) from the device into dest_dir.

        Returns local Path objects, base.apk first. Reuses already-pulled files
        when reuse=True. Shared by the JADX/apktool/static-analysis tools.
        """
        remote_paths = self.apk_remote_paths(package_name)
        if not remote_paths:
            raise RuntimeError(
                f"Package '{package_name}' not found on device (no APK path).")

        remote_paths.sort(key=lambda p: (0 if p.endswith("base.apk") else 1, p))
        if not include_splits:
            base = [p for p in remote_paths if p.endswith("base.apk")]
            remote_paths = base or remote_paths[:1]

        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)

        local_apks = []
        for remote in remote_paths:
            local = dest / Path(remote).name
            if not (reuse and local.is_file() and local.stat().st_size > 0):
                self.device.pull(remote, str(local))
            local_apks.append(local)
        return local_apks

    def get_logcat(self, lines: int = 200, filter_spec: str = "",
                   priority: str = "") -> str:
        """Dump recent logcat output.

        Args:
            lines: tail size (most recent N lines).
            filter_spec: optional tag filter, e.g. "ActivityManager:I *:S".
            priority: optional minimum priority for all tags (V/D/I/W/E/F).
        """
        cmd = f"logcat -d -t {int(lines)}"
        if priority:
            cmd += f" *:{priority}"
        if filter_spec:
            cmd += f" {filter_spec}"
        return self.device.shell(cmd)

    def push_file(self, local_path: str, device_path: str) -> str:
        """Push a host file to the device (e.g. a sample APK, tool, or payload)."""
        p = Path(local_path)
        if not p.is_file():
            raise RuntimeError(f"Local file not found: {local_path}")
        self.device.push(str(p), device_path)
        return f"Pushed {p} -> {device_path} ({p.stat().st_size} bytes)"

    def pull_file(self, device_path: str, local_path: str = "") -> str:
        """Pull a file from the device to the host (e.g. a dropped payload).

        Defaults to workspace/pulled/<name> when local_path is omitted.
        """
        if local_path:
            dest = Path(local_path)
        else:
            dest = _HERE / "workspace" / "pulled" / Path(device_path).name
        dest.parent.mkdir(parents=True, exist_ok=True)
        self.device.pull(device_path, str(dest))
        if not dest.exists():
            raise RuntimeError(f"Pull produced no file for {device_path}")
        return f"Pulled {device_path} -> {dest} ({dest.stat().st_size} bytes)"

    def install_apk(self, apk_path: str, reinstall: bool = False,
                    grant_permissions: bool = False, downgrade: bool = False) -> str:
        """Install a host APK onto the device (adb install)."""
        p = Path(apk_path)
        if not p.is_file():
            raise RuntimeError(f"APK not found: {apk_path}")
        try:
            self.device.install(
                str(p), reinstall=reinstall, downgrade=downgrade,
                grand_all_permissions=grant_permissions)
        except Exception as e:
            raise RuntimeError(f"Install failed for {p.name}: {e}")
        return (f"Installed {p.name} "
                f"(reinstall={reinstall}, grant={grant_permissions}, downgrade={downgrade})")

    def take_screenshot(self) -> str:
        self.device.shell("screencap -p /sdcard/screenshot.png")
        self.device.pull("/sdcard/screenshot.png", SCREENSHOT_PATH)
        self.device.shell("rm /sdcard/screenshot.png")

        # compressing the ss to avoid "maximum call stack exceeded" error on claude desktop
        with PILImage.open(SCREENSHOT_PATH) as img:
            width, height = img.size
            new_width = int(width * 0.3)
            new_height = int(height * 0.3)
            resized_img = img.resize(
                (new_width, new_height), PILImage.Resampling.LANCZOS
            )
            resized_img.save(
                COMPRESSED_PATH, "PNG", quality=85, optimize=True
            )
        return COMPRESSED_PATH

    def get_uilayout(self) -> str:
        self.device.shell("uiautomator dump")
        self.device.pull("/sdcard/window_dump.xml", "window_dump.xml")
        self.device.shell("rm /sdcard/window_dump.xml")

        import re
        import xml.etree.ElementTree as ET

        def calculate_center(bounds_str):
            matches = re.findall(r"\[(\d+),(\d+)\]", bounds_str)
            if len(matches) == 2:
                x1, y1 = map(int, matches[0])
                x2, y2 = map(int, matches[1])
                center_x = (x1 + x2) // 2
                center_y = (y1 + y2) // 2
                return center_x, center_y
            return None

        tree = ET.parse("window_dump.xml")
        root = tree.getroot()

        clickable_elements = []
        for element in root.findall(".//node[@clickable='true']"):
            text = element.get("text", "")
            content_desc = element.get("content-desc", "")
            bounds = element.get("bounds", "")

            # Only include elements that have either text or content description
            if text or content_desc:
                center = calculate_center(bounds)
                element_info = "Clickable element:"
                if text:
                    element_info += f"\n  Text: {text}"
                if content_desc:
                    element_info += f"\n  Description: {content_desc}"
                element_info += f"\n  Bounds: {bounds}"
                if center:
                    element_info += f"\n  Center: ({center[0]}, {center[1]})"
                clickable_elements.append(element_info)

        if not clickable_elements:
            return "No clickable elements found with text or description"
        else:
            result = "\n\n".join(clickable_elements)
            return result
