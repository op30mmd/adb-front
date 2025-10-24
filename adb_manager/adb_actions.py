import subprocess
import os
import re
import sys
from pathlib import Path

from adb_manager.adb_thread import ADBThread
from adb_manager.interactive_shell_thread import InteractiveShellThread
from adb_manager.logcat_thread import LogcatThread

def get_adb_path():
    """Get the path to the bundled adb executable"""
    if hasattr(sys, '_MEIPASS'):
        # Running in a PyInstaller bundle
        base_path = os.path.join(sys._MEIPASS, 'adb_binary')
    else:
        # Running in a normal Python environment
        base_path = os.path.abspath("./adb_binary")

    if sys.platform.startswith('win32'):
        return os.path.join(base_path, 'adb.exe')
    elif sys.platform.startswith('linux'):
        return os.path.join(base_path, 'adbl')
    else:
        return os.path.join(base_path, 'adb')

class ADBCore:
    def __init__(self):
        self.adb_path = get_adb_path()
        if not self.is_adb_available():
            raise RuntimeError(f"ADB not found at {self.adb_path}")
        self.shell_thread = None
        self.adb_command_thread = None
        self.logcat_thread = None
        self.interactive_shell_thread = None
        self.current_device = None

    def is_adb_available(self):
        """Check if adb is available"""
        return os.path.exists(self.adb_path)

    def get_adb_cmd(self, *args):
        cmd = [self.adb_path]
        if self.current_device:
            cmd.extend(["-s", self.current_device])
        cmd.extend(args)
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
        self.stop_interactive_shell()
        self.current_device = device if device else None

    def start_interactive_shell(self):
        if not self.current_device:
            raise RuntimeError("No device selected")
            
        if self.interactive_shell_thread and self.interactive_shell_thread.is_alive():
            return

        self.interactive_shell_thread = InteractiveShellThread(self.current_device)
        self.interactive_shell_thread.start()

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
            cmd = self.get_adb_cmd("shell", f"ls -lA '{path}'")
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True, encoding='utf-8', errors='replace', creationflags=creation_flags)
            
            files = []
            if not result.stdout:
                return files
            
            for line in result.stdout.splitlines():
                if not line.strip() or "->" in line or line.startswith("total"): # Ignore links for now
                    continue

                match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})', line)
                if match:
                    datetime_str = match.group(1)
                    parts = line.split(datetime_str)
                    details = parts[0]
                    name = parts[1].strip()
                    
                    detail_parts = details.split()
                    if len(detail_parts) >= 2:
                        perms = detail_parts[0]
                        size = detail_parts[-1]
                        
                        file_type = "Directory" if perms.startswith('d') else "File"
                        files.append({"name": name, "type": file_type, "size": size, "permissions": perms})

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
        pass

    def stop_interactive_shell(self):
        if self.interactive_shell_thread:
            self.interactive_shell_thread.stop()
            self.interactive_shell_thread = None

    def send_ctrl_c_to_shell(self):
        if self.interactive_shell_thread and self.interactive_shell_thread.isRunning():
            self.interactive_shell_thread.send_ctrl_c()

    def execute_shell_command(self, command):
        """Execute shell command"""
        if not self.current_device:
            raise RuntimeError("No device selected")
            
        if not self.interactive_shell_thread or not self.interactive_shell_thread.isRunning():
            self.start_interactive_shell()

        if not command:
            return
            
        self.interactive_shell_thread.send_command(command)
        
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
                
    def screen_record(self, save_path):
        """Record screen"""
        if not self.current_device:
            raise RuntimeError("No device selected")
            
        temp_path = "/sdcard/screenrecord.mp4"

        try:
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW
            subprocess.run(self.get_adb_cmd("shell", "screenrecord", "--time-limit", "30", temp_path), timeout=35, check=True, creationflags=creation_flags)
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