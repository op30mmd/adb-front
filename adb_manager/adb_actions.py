import subprocess
import os
import re
import sys
import shlex
from pathlib import Path
import logging

from adb_manager.adb_thread import ADBThread

from adb_manager.logcat_thread import LogcatThread
from PyQt6.QtCore import QObject, pyqtSignal
import os
import sys
import threading
import time

def get_adb_path():
    """Get the path to the bundled adb executable, ensuring compatibility"""
    try:
        if hasattr(sys, '_MEIPASS'):
            # PyInstaller bundle
            base_path = os.path.join(sys._MEIPASS, 'adb_binary')
        else:
            # Development environment
            base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'adb_binary'))

        platform_map = {
            'win32': 'windows/adb.exe',
            'linux': 'linux/adbl',
            'darwin': 'macos/adb'
        }

        platform_key = sys.platform
        if platform_key not in platform_map:
            raise RuntimeError(f"Unsupported platform: {platform_key}")

        adb_path = os.path.join(base_path, platform_map[platform_key])

        if not os.path.exists(adb_path):
            raise FileNotFoundError(f"ADB binary not found at: {adb_path}")

        # Ensure execute permissions on non-Windows platforms
        if platform_key != 'win32':
            os.chmod(adb_path, 0o755)

        return adb_path
    except Exception as e:
        # Log the error for debugging
        logging.error(f"Error resolving ADB path: {e}")
        # Return a path that will fail the is_adb_available check,
        # leading to a graceful error message in the UI.
        return ""

class ADBCore(QObject):
    shell_output = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.adb_path = get_adb_path()
        if not self.is_adb_available():
            raise RuntimeError(f"ADB not found at {self.adb_path}")
        self.shell_thread = None
        self.adb_command_thread = None

        self.current_device = None

    def is_adb_available(self):
        """Check if adb is available"""
        return os.path.exists(self.adb_path)

    def get_adb_cmd(self, *args):
        cmd = [self.adb_path]
        if self.current_device:
            cmd.extend(["-s", self.current_device])

        # Quote arguments to handle spaces and special characters
        for arg in args:
            if sys.platform != 'win32':
                cmd.append(shlex.quote(arg))
            else:
                cmd.append(arg)
        return cmd

    def run_adb_command(self, command, callback=None):
        """Run ADB command and handle output"""
        if not self.current_device:
            raise RuntimeError("No device selected")

        if self.adb_command_thread and self.adb_command_thread.isRunning():
            raise RuntimeError("An ADB command is already running.")
            
        self.adb_command_thread = ADBThread(command)
        if callback:
            self.adb_command_thread.output.connect(callback)
        self.adb_command_thread.error.connect(lambda err: self.handle_command_error(err))
        self.adb_command_thread.start()
        
    def handle_command_error(self, error):
        """Handle command error"""
        if error.strip():
            raise RuntimeError(error)
        
    def refresh_devices(self):
        """Refresh list of connected devices"""
        try:
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW

            result = subprocess.run(self.get_adb_cmd("devices"), 
                                  capture_output=True, text=True, check=True, 
                                  encoding='utf-8', errors='replace',
                                  creationflags=creation_flags)
            devices = []
            
            for line in result.stdout.split('\n')[1:]:
                if line.strip() and 'device' in line:
                    device = line.split('\t')[0].strip()
                    if device:
                        devices.append(device)
            
            return devices
                
        except (FileNotFoundError, subprocess.CalledProcessError, Exception) as e:
            raise RuntimeError(f"Failed to refresh devices: {e}")

    def on_device_changed(self, device):
        """Handle device selection change"""
        self.current_device = device if device else None



    def start_adb_server(self):
        """Start ADB server"""
        try:
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW

            subprocess.run(self.get_adb_cmd("start-server"), check=True, creationflags=creation_flags)
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            raise RuntimeError(f"Failed to start ADB server: {e}")

    def kill_adb_server(self):
        """Kill ADB server"""
        try:
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW

            subprocess.run(self.get_adb_cmd("kill-server"), check=True, creationflags=creation_flags)
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            raise RuntimeError(f"Failed to kill ADB server: {e}")
        
    def load_device_info(self):
        """Load device information"""
        if not self.current_device:
            raise RuntimeError("No device selected")
            
        info_commands = [
            ("Model", ["shell", "getprop", "ro.product.model"]),
            ("Manufacturer", ["shell", "getprop", "ro.product.manufacturer"]),
            ("Brand", ["shell", "getprop", "ro.product.brand"]),
            ("Product Name", ["shell", "getprop", "ro.product.name"]),
            ("Device", ["shell", "getprop", "ro.product.device"]),
            ("Android Version", ["shell", "getprop", "ro.build.version.release"]),
            ("SDK Version", ["shell", "getprop", "ro.build.version.sdk"]),
            ("Build ID", ["shell", "getprop", "ro.build.id"]),
            ("Display ID", ["shell", "getprop", "ro.build.display.id"]),
            ("Incremental Version", ["shell", "getprop", "ro.build.version.incremental"]),
            ("Codename", ["shell", "getprop", "ro.build.version.codename"]),
            ("Tags", ["shell", "getprop", "ro.build.tags"]),
            ("Type", ["shell", "getprop", "ro.build.type"]),
            ("User", ["shell", "getprop", "ro.build.user"]),
            ("Host", ["shell", "getprop", "ro.build.host"]),
            ("Build Date", ["shell", "getprop", "ro.build.date"]),
            ("Build Date (UTC)", ["shell", "getprop", "ro.build.date.utc"]),
            ("Fingerprint", ["shell", "getprop", "ro.build.fingerprint"]),
            ("CPU ABI", ["shell", "getprop", "ro.product.cpu.abi"]),
            ("CPU ABI2", ["shell", "getprop", "ro.product.cpu.abi2"]),
            ("Locale", ["shell", "getprop", "ro.product.locale"]),
            ("Screen Density", ["shell", "getprop", "ro.sf.lcd_density"]),
            ("Timezone", ["shell", "getprop", "persist.sys.timezone"]),
            ("Phone Type", ["shell", "getprop", "gsm.current.phone-type"]),
            ("SIM Operator", ["shell", "getprop", "gsm.sim.operator.alpha"]),
            ("SIM State", ["shell", "getprop", "gsm.sim.state"]),
            ("Hostname", ["shell", "getprop", "net.hostname"]),
            ("Ethernet IP", ["shell", "getprop", "dhcp.eth0.ipaddress"]),
            ("WiFi IP", ["shell", "getprop", "dhcp.wlan0.ipaddress"]),
            ("Screen Resolution", ["shell", "wm", "size"]),
        ]
        
        all_info = [("Serial Number", self.current_device)]

        for label, cmd_args in info_commands:
            try:
                cmd = self.get_adb_cmd(*cmd_args)
                creation_flags = 0
                if sys.platform == "win32":
                    creation_flags = subprocess.CREATE_NO_WINDOW
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=True, encoding='utf-8', errors='replace', creationflags=creation_flags)
                value = result.stdout.strip()
                if value:
                    all_info.append((label, value))
            except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                raise RuntimeError(f"Failed to get device property: {e}")

        return all_info
        
    def load_battery_info(self):
        """Load battery information"""
        if not self.current_device:
            raise RuntimeError("No device selected")
            
        try:
            cmd = self.get_adb_cmd("shell", "dumpsys", "battery")
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(cmd, 
                                  capture_output=True, text=True, timeout=5, check=True, encoding='utf-8', errors='replace', creationflags=creation_flags)
            
            battery_info = {}
            for line in result.stdout.splitlines():
                match = re.match(r'  \s*(.*?): (.*)', line)
                if match:
                    key = match.group(1).strip()
                    value = match.group(2).strip()
                    battery_info[key] = value
            
            return battery_info

        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"Error loading battery info: {e}")
            
    def browse_device_path(self, path):
        """Browse device file system"""
        if not self.current_device:
            raise RuntimeError("No device selected")

        try:
            cmd = self.get_adb_cmd("shell", "ls", "-la", path)
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True, encoding='utf-8', errors='replace', creationflags=creation_flags)

            files = []
            if not result.stdout:
                return files

            # Regex to match ls -la output with different date formats
            ls_pattern = re.compile(
                r'^(?P<permissions>[\w-]+)\s+'
                r'(?P<links>\d+)\s+'
                r'(?P<owner>\S+)\s+'
                r'(?P<group>\S+)\s+'
                r'(?P<size>\d+)\s+'
                r'(?P<date>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}|\w+\s+\d+\s+\d{2}:\d{2}|\w+\s+\d+\s+\d{4})\s+'
                r'(?P<name>.+)$'
            )

            for line in result.stdout.splitlines():
                if not line.strip() or line.startswith("total"):
                    continue

                match = ls_pattern.match(line)
                if match:
                    details = match.groupdict()
                    name = details['name']

                    # Skip '.' and '..' directories
                    if name in ['.', '..'] or "->" in name:
                        continue

                    file_type = "Directory" if details['permissions'].startswith('d') else "File"

                    files.append({
                        "name": name,
                        "type": file_type,
                        "size": details['size'],
                        "permissions": details['permissions']
                    })
                else:
                    logging.warning(f"Could not parse ls line: {line}")

            return files

        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"Failed to browse path: {e}")
            
    def pull_file(self, source, dest, callback=None):
        """Pull file from device"""
        cmd = self.get_adb_cmd("pull", source, dest)
        self.run_adb_command(cmd, callback)
            
    def push_file(self, source, dest, callback=None):
        """Push file to device"""
        cmd = self.get_adb_cmd("push", source, dest)
        self.run_adb_command(cmd, callback)
            
    def delete_file(self, path, callback=None):
        """Delete file from device"""
        cmd = self.get_adb_cmd("shell", "rm", "-rf", path)
        self.run_adb_command(cmd, callback)
            
    def create_directory(self, path, callback=None):
        """Create directory on device"""
        cmd = self.get_adb_cmd("shell", "mkdir", "-p", path)
        self.run_adb_command(cmd, callback)
            
    def handle_shell_output(self, text):
        self.shell_output.emit(text)








        
    def list_packages(self, pkg_type):
        """List installed packages"""
        if not self.current_device:
            raise RuntimeError("No device selected")
            
        cmd_args = ["shell", "pm", "list", "packages"]
        if pkg_type == "system":
            cmd_args.append("-s")
        elif pkg_type == "3rd":
            cmd_args.append("-3")
            
        try:
            cmd = self.get_adb_cmd(*cmd_args)
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True, encoding='utf-8', errors='replace', creationflags=creation_flags)
            packages = [line.replace('package:', '').strip() for line in result.stdout.split('\n') if line.strip()]
            
            return sorted(packages)
            
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"Failed to list packages: {e}")
            
    def install_apk(self, apk_path, callback=None):
        """Install APK file"""
        cmd = self.get_adb_cmd("install", apk_path)
        self.run_adb_command(cmd, callback)
            
    def uninstall_app(self, package, callback=None):
        """Uninstall selected app"""
        cmd = self.get_adb_cmd("uninstall", package)
        self.run_adb_command(cmd, callback)
            
    def clear_app_data(self, package, callback=None):
        """Clear app data"""
        cmd = self.get_adb_cmd("shell", "pm", "clear", package)
        self.run_adb_command(cmd, callback)
        
    def force_stop_app(self, package, callback=None):
        """Force stop app"""
        cmd = self.get_adb_cmd("shell", "am", "force-stop", package)
        self.run_adb_command(cmd, callback)
        
    def take_screenshot(self, save_path):
        """Take screenshot"""
        if not self.current_device:
            raise RuntimeError("No device selected")
            
        temp_path = "/sdcard/screenshot.png"
        try:
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW
            subprocess.run(self.get_adb_cmd("shell", "screencap", "-p", temp_path), timeout=5, check=True, creationflags=creation_flags)
            subprocess.run(self.get_adb_cmd("pull", temp_path, save_path), timeout=10, check=True, creationflags=creation_flags)
            subprocess.run(self.get_adb_cmd("shell", "rm", temp_path), timeout=5, check=True, creationflags=creation_flags)
            return True
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"Failed to take screenshot: {e}")
                
    def screen_record(self, save_path, resolution=None, bitrate=None, time_limit="30"):
        """Record screen"""
        if not self.current_device:
            raise RuntimeError("No device selected")

        temp_path = "/sdcard/screenrecord.mp4"

        try:
            record_cmd = ["shell", "screenrecord"]
            if resolution:
                record_cmd.extend(["--size", resolution])
            if bitrate:
                record_cmd.extend(["--bit-rate", bitrate])

            record_cmd.extend(["--time-limit", time_limit])
            record_cmd.append(temp_path)

            # Timeout should be slightly longer than the recording time limit
            timeout = int(time_limit) + 5

            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW
            subprocess.run(self.get_adb_cmd(*record_cmd), timeout=timeout, check=True, creationflags=creation_flags)
            subprocess.run(self.get_adb_cmd("pull", temp_path, save_path), timeout=30, check=True, creationflags=creation_flags)
            subprocess.run(self.get_adb_cmd("shell", "rm", temp_path), timeout=5, check=True, creationflags=creation_flags)
            return True
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"Failed to record screen: {e}")
                
    def enable_wifi_adb(self):
        """Enable WiFi ADB"""
        if not self.current_device:
            raise RuntimeError("No device selected")
            
        try:
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW
            subprocess.run(self.get_adb_cmd("tcpip", "5555"), timeout=5, check=True, creationflags=creation_flags)
            
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(self.get_adb_cmd("shell", "ip", "addr"), 
                                  capture_output=True, text=True, timeout=5, check=True, 
                                  encoding='utf-8', errors='replace', creationflags=creation_flags)
            
            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/.*scope global.*wlan', result.stdout)
            
            if ip_match:
                return ip_match.group(1)
            else:
                return "Enabled"
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"Failed to enable WiFi ADB: {e}")
            
    def connect_wifi_adb(self, ip):
        """Connect to device via WiFi"""
        try:
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(self.get_adb_cmd("connect", ip),
                                  capture_output=True, text=True, timeout=10, check=True, encoding='utf-8', errors='replace', creationflags=creation_flags)
            return result.stdout
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"Failed to connect: {e}")
                
    def backup_device(self, save_path, callback=None):
        """Backup device"""
        cmd = self.get_adb_cmd("backup", "-all", "-f", save_path)
        self.run_adb_command(cmd, callback)
            
    def restore_device(self, backup_path, callback=None):
        """Restore device"""
        cmd = self.get_adb_cmd("restore", backup_path)
        self.run_adb_command(cmd, callback)
            
    def start_logcat_thread(self, callback):
        """Start logcat monitoring"""
        if not self.current_device:
            raise RuntimeError("No device selected")

        self.logcat_thread = LogcatThread(self.current_device)
        self.logcat_thread.log_line.connect(callback)
        self.logcat_thread.start()

    def stop_logcat_thread(self):
        """Stop logcat monitoring"""
        if self.logcat_thread:
            self.logcat_thread.stop()
            self.logcat_thread = None

    def clear_logcat(self):
        """Clear logcat buffer"""
        if self.current_device:
            try:
                creation_flags = 0
                if sys.platform == "win32":
                    creation_flags = subprocess.CREATE_NO_WINDOW
                subprocess.run(self.get_adb_cmd("logcat", "-c"), check=True, creationflags=creation_flags)
            except (FileNotFoundError, subprocess.CalledProcessError) as e:
                raise RuntimeError(f"Failed to clear logcat: {e}")

    def cleanup(self):
        """Clean up resources before exiting"""
        self.stop_logcat_thread()
        if self.adb_command_thread and self.adb_command_thread.isRunning():
            self.adb_command_thread.quit()
            self.adb_command_thread.wait()