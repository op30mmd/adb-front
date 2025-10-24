import subprocess
import os
import re
import shutil
import sys
import io
import shlex
from pathlib import Path
from PyQt6.QtCore import QTimer

from adb_manager.adb_thread import ADBThread
from adb_manager.interactive_shell_thread import InteractiveShellThread

def get_adb_path():
    """Get the path to the bundled adb executable"""
    if hasattr(sys, '_MEIPASS'):
        # Running in a PyInstaller bundle
        return os.path.join(sys._MEIPASS, 'adb_binary', 'adb.exe')
    # Running in a normal Python environment
    return os.path.join(os.path.abspath("."), "adb_binary", "adb.exe")

class ADBCore:
    def __init__(self):
        self.adb_path = get_adb_path()
        if not self.is_adb_available():
            raise RuntimeError(f"ADB not found at {self.adb_path}")
        self.logcat_timer = QTimer()
        self.logcat_timer.timeout.connect(self.read_logcat)
        self.logcat_process = None
        self.shell_thread = None
        self.adb_command_thread = None
        self.interactive_shell_thread = None
        self.shell_output_timer = QTimer()
        self.shell_output_timer.timeout.connect(self.poll_shell_output)
        self.current_device = None

    def poll_shell_output(self):
        if self.interactive_shell_thread and self.interactive_shell_thread.is_alive():
            output = self.interactive_shell_thread.get_output()
            if output:
                self.handle_shell_output(output)

    def is_adb_available(self):
        """Check if adb is available"""
        return os.path.exists(self.adb_path)

    def get_adb_cmd(self, *args):
        cmd = [self.adb_path]
        if self.main.current_device:
            cmd.extend(["-s", self.main.current_device])
        cmd.extend(args)
        return cmd

    def run_adb_command(self, command, callback=None, error_callback=None):
        """Run ADB command and handle output"""
        if self.adb_command_thread and self.adb_command_thread.isRunning():
            if error_callback:
                error_callback("Busy", "An ADB command is already running.")
            return

        if not self.check_device(error_callback):
            return
            
        self.adb_command_thread = ADBThread(command)
        self.adb_command_thread.output.connect(lambda out: self.handle_command_output(out, callback))
        self.adb_command_thread.error.connect(lambda err: self.handle_command_error(err, error_callback))
        self.adb_command_thread.start()
        
    def handle_command_output(self, output, callback=None):
        """Handle command output"""
        if callback:
            callback(output)
            
    def handle_command_error(self, error, error_callback=None):
        """Handle command error"""
        if error.strip() and error_callback:
            error_callback("Error", error)
            
    def check_device(self, error_callback=None):
        """Check if device is connected"""
        if not self.current_device:
            if error_callback:
                error_callback("No Device", "No device selected. Please connect a device.")
            return False
        return True
        
    def refresh_devices(self, device_combo, status_label):
        """Refresh list of connected devices"""
        try:
            # Set up environment for Windows
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
            
            device_combo.clear()
            device_combo.addItems(devices)
            
            if devices:
                self.current_device = devices[0]
                status_label.setText(f"Connected to: {self.current_device}")
            else:
                self.current_device = None
                status_label.setText("No devices connected")
                
        except FileNotFoundError:
            # This should not happen, as we check for adb on startup
            pass
        except (subprocess.CalledProcessError, Exception) as e:
            # Ignore errors
            pass
            
    def on_device_changed(self, device, status_label, device_info_table, battery_table, path_edit, file_tree, progress_bar, apps_list):
        """Handle device selection change"""
        self.stop_interactive_shell()
        self.current_device = device if device else None
        if self.current_device:
            status_label.setText(f"Connected to: {self.current_device}")
            self.load_device_info(device_info_table, self.current_device)
            self.load_battery_info(battery_table, self.current_device)
            self.browse_device_path(path_edit.text(), file_tree, progress_bar, self.current_device)
            self.list_packages("all", apps_list, self.current_device)

    def start_interactive_shell(self):
        if not self.check_device():
            return
            
        if self.interactive_shell_thread and self.interactive_shell_thread.is_alive():
            return

        self.interactive_shell_thread = InteractiveShellThread(self.main.current_device)
        self.interactive_shell_thread.start()
        self.shell_output_timer.start(100)

    def start_adb_server(self, refresh_devices_callback):
        """Start ADB server"""
        try:
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW

            subprocess.run(self.get_adb_cmd("start-server"), check=True, creationflags=creation_flags)
            refresh_devices_callback()
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            # Ignore errors
            pass

    def kill_adb_server(self, device_combo, status_label):
        """Kill ADB server"""
        try:
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW

            subprocess.run(self.get_adb_cmd("kill-server"), check=True, creationflags=creation_flags)
            device_combo.clear()
            self.current_device = None
            status_label.setText("No devices connected")
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            # Ignore errors
            pass
        
    def load_device_info(self, device_info_table, current_device):
        """Load device information"""
        if not self.check_device():
            return
            
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
        
        device_info_table.setRowCount(0)
        
        all_info = [("Serial Number", current_device)]

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
                pass # Ignore errors for properties that don't exist

        device_info_table.setRowCount(len(all_info))
        for row, (label, value) in enumerate(all_info):
            device_info_table.setItem(row, 0, QTableWidgetItem(label))
            device_info_table.setItem(row, 1, QTableWidgetItem(value))
        
    def load_battery_info(self, battery_table, current_device):
        """Load battery information"""
        if not self.check_device():
            return
            
        try:
            cmd = self.get_adb_cmd("shell", "dumpsys", "battery")
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(cmd, 
                                  capture_output=True, text=True, timeout=5, check=True, encoding='utf-8', errors='replace', creationflags=creation_flags)
            
            battery_table.setRowCount(0)
            battery_info = {}
            for line in result.stdout.splitlines():
                match = re.match(r'  \s*(.*?): (.*)', line)
                if match:
                    key = match.group(1).strip()
                    value = match.group(2).strip()
                    battery_info[key] = value
            
            row = 0
            for key, value in battery_info.items():
                battery_table.insertRow(row)
                battery_table.setItem(row, 0, QTableWidgetItem(key.replace("_", " ").title()))
                
                if key == 'temperature':
                    value = f"{int(value) / 10}°C"
                elif key == 'status':
                    status_map = {
                        '1': 'Unknown',
                        '2': 'Charging',
                        '3': 'Discharging',
                        '4': 'Not charging',
                        '5': 'Full',
                    }
                    value = status_map.get(value, value)
                elif key == 'health':
                    health_map = {
                        '1': 'Unknown',
                        '2': 'Good',
                        '3': 'Overheat',
                        '4': 'Dead',
                        '5': 'Over voltage',
                        '6': 'Unspecified failure',
                        '7': 'Cold',
                    }
                    value = health_map.get(value, value)

                battery_table.setItem(row, 1, QTableWidgetItem(str(value)))
                row += 1

        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            battery_table.setRowCount(0)
            battery_table.insertRow(0)
            battery_table.setItem(0, 0, QTableWidgetItem("Error"))
            battery_table.setItem(0, 1, QTableWidgetItem(f"Error loading battery info: {e}"))
            
    def browse_device_path(self, path, file_tree, progress_bar, current_device, error_callback=None):
        """Browse device file system"""
        if not self.check_device(error_callback):
            return
            
        # Show loading indicator
        progress_bar.setRange(0, 0) # Indeterminate
        progress_bar.setVisible(True)
        
        try:
            cmd = self.get_adb_cmd("shell", f"ls -lA '{path}'")
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True, encoding='utf-8', errors='replace', creationflags=creation_flags)
            
            file_tree.clear()
            
            if not result.stdout:
                if error_callback:
                    error_callback("Error", "No output from ls command. Path may not exist or is empty.")
                return
            
            icon_provider = QFileIconProvider()
            for line in result.stdout.splitlines():
                if not line.strip() or "->" in line or line.startswith("total"): # Ignore links for now
                    continue

                # Find date and time in the line
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
                        item = QTreeWidgetItem([name, file_type, size, perms])
                        
                        if file_type == "Directory":
                            item.setIcon(0, icon_provider.icon(QFileIconProvider.IconType.Folder))
                        else:
                            item.setIcon(0, icon_provider.icon(QFileIconProvider.IconType.File))

                        file_tree.addTopLevelItem(item)

            if file_tree.topLevelItemCount() == 0:
                if error_callback:
                    error_callback("Info", "Directory is empty or could not be read.")
                            
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            if error_callback:
                error_callback("Error", f"Failed to browse path: {e}")
        finally:
            # Hide loading indicator
            progress_bar.setVisible(False)
            
    def on_file_double_click(self, item):
        """Handle double click on file/directory"""
        name = item.text(0)
        file_type = item.text(1)
        
        if file_type == "Directory":
            if self.main.device_path.endswith('/'):
                self.main.device_path += name
            else:
                self.main.device_path += '/' + name
            self.main.path_edit.setText(self.main.device_path)
            self.browse_device_path()
            
    def go_parent_directory(self):
        """Go to parent directory"""
        path = Path(self.main.device_path)
        parent = str(path.parent)
        if parent != self.main.device_path:
            self.main.device_path = parent
            self.main.path_edit.setText(self.main.device_path)
            self.browse_device_path()

    def go_home(self):
        """Go to home directory (/sdcard/)"""
        self.main.path_edit.setText("/sdcard/")
        self.browse_device_path()
            
    def pull_file(self, selected_item, device_path, current_device, error_callback=None):
        """Pull file from device"""
        if not self.check_device(error_callback):
            return
            
        if not selected_item:
            if error_callback:
                error_callback("Warning", "Please select a file")
            return
            
        filename = selected_item.text(0)
        source = f"{device_path}/{filename}".replace('//', '/')
        
        dest, _ = QFileDialog.getSaveFileName(None, "Save File", filename)
        if dest:
            cmd = self.get_adb_cmd("pull", source, dest)
            self.run_adb_command(cmd, lambda out: error_callback("Success", "File pulled successfully"))
            
    def push_file(self, device_path, current_device, browse_device_path_callback, error_callback=None):
        """Push file to device"""
        if not self.check_device(error_callback):
            return
            
        source, _ = QFileDialog.getOpenFileName(None, "Select File")
        if source:
            dest = f"{device_path}/{os.path.basename(source)}".replace('//', '/')
            cmd = self.get_adb_cmd("push", source, dest)
            self.run_adb_command(cmd, lambda out: browse_device_path_callback())
            
    def delete_file(self, selected_item, device_path, current_device, browse_device_path_callback, error_callback=None):
        """Delete file from device"""
        if not self.check_device(error_callback):
            return
            
        if not selected_item:
            if error_callback:
                error_callback("Warning", "Please select a file")
            return
            
        filename = selected_item.text(0)
        
        reply = QMessageBox.question(None, "Confirm", f"Delete {filename}?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            path = f"{device_path}/{filename}".replace('//', '/')
            cmd = self.get_adb_cmd("shell", "rm", "-rf", path)
            self.run_adb_command(cmd, lambda out: browse_device_path_callback())
            
    def create_directory(self, device_path, current_device, browse_device_path_callback, error_callback=None):
        """Create directory on device"""
        if not self.check_device(error_callback):
            return
            
        name, ok = QInputDialog.getText(None, "New Folder", "Folder name:")
        if ok and name:
            path = f"{device_path}/{name}".replace('//', '/')
            cmd = self.get_adb_cmd("shell", "mkdir", "-p", path)
            self.run_adb_command(cmd, lambda out: browse_device_path_callback())
            
    def handle_shell_output(self, text):
        cursor = self.main.shell_output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.main.shell_output.setTextCursor(cursor)
        self.main.shell_output.insertPlainText(text)

    def start_interactive_shell(self):
        if not self.check_device():
            return
            
        if self.interactive_shell_thread and self.interactive_shell_thread.isRunning():
            return

        print(f"--- Starting interactive shell for device: {self.main.current_device} ---")
        self.interactive_shell_thread = InteractiveShellThread(self.main.current_device)
        self.interactive_shell_thread.output.connect(self.handle_shell_output)
        self.interactive_shell_thread.start()

    def stop_interactive_shell(self):
        if self.interactive_shell_thread:
            self.interactive_shell_thread.stop()
            self.interactive_shell_thread = None

    def send_ctrl_c_to_shell(self):
        if self.interactive_shell_thread and self.interactive_shell_thread.isRunning():
            self.interactive_shell_thread.send_ctrl_c()

    def execute_shell_command(self, command, shell_output, current_device, error_callback=None):
        """Execute shell command"""
        if not self.check_device(error_callback):
            return
            
        if not self.interactive_shell_thread or not self.interactive_shell_thread.isRunning():
            self.start_interactive_shell()

        if not command:
            return
            
        self.interactive_shell_thread.send_command(command)
        shell_output.clear()
        
    def list_packages(self, pkg_type, apps_list, current_device, error_callback=None):
        """List installed packages"""
        if not self.check_device(error_callback):
            return
            
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
            
            apps_list.clear()
            apps_list.addItems(sorted(packages))
            
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            if error_callback:
                error_callback("Error", f"Failed to list packages: {e}")
            
    def install_apk(self, current_device, error_callback=None):
        """Install APK file"""
        if not self.check_device(error_callback):
            return
            
        apk_path, _ = QFileDialog.getOpenFileName(None, "Select APK", "", "APK Files (*.apk)")
        if apk_path:
            cmd = self.get_adb_cmd("install", apk_path)
            self.run_adb_command(cmd, lambda out: error_callback("Success", "APK installed"))
            
    def uninstall_app(self, selected_item, current_device, list_packages_callback, error_callback=None):
        """Uninstall selected app"""
        if not self.check_device(error_callback):
            return
            
        if not selected_item:
            if error_callback:
                error_callback("Warning", "Please select an app")
            return
            
        package = selected_item.text()
        reply = QMessageBox.question(None, "Confirm", f"Uninstall {package}?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            cmd = self.get_adb_cmd("uninstall", package)
            self.run_adb_command(cmd, lambda out: list_packages_callback("3rd"))
            
    def clear_app_data(self, selected_item, current_device, error_callback=None):
        """Clear app data"""
        if not self.check_device(error_callback):
            return
            
        if not selected_item:
            if error_callback:
                error_callback("Warning", "Please select an app")
            return
            
        package = selected_item.text()
        cmd = self.get_adb_cmd("shell", "pm", "clear", package)
        self.run_adb_command(cmd)
        
    def force_stop_app(self, selected_item, current_device, error_callback=None):
        """Force stop app"""
        if not self.check_device(error_callback):
            return
            
        if not selected_item:
            if error_callback:
                error_callback("Warning", "Please select an app")
            return
            
        package = selected_item.text()
        cmd = self.get_adb_cmd("shell", "am", "force-stop", package)
        self.run_adb_command(cmd)
        
    def take_screenshot(self, current_device, error_callback=None):
        """Take screenshot"""
        if not self.check_device(error_callback):
            return
            
        save_path, _ = QFileDialog.getSaveFileName(None, "Save Screenshot", "screenshot.png", 
                                                "PNG Files (*.png)")
        if save_path:
            temp_path = "/sdcard/screenshot.png"
            try:
                creation_flags = 0
                if sys.platform == "win32":
                    creation_flags = subprocess.CREATE_NO_WINDOW
                subprocess.run(self.get_adb_cmd("shell", "screencap", "-p", temp_path), timeout=5, check=True, creationflags=creation_flags)
                subprocess.run(self.get_adb_cmd("pull", temp_path, save_path), timeout=10, check=True, creationflags=creation_flags)
                subprocess.run(self.get_adb_cmd("shell", "rm", temp_path), timeout=5, check=True, creationflags=creation_flags)
                if error_callback:
                    error_callback("Success", "Screenshot saved")
            except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                if error_callback:
                    error_callback("Error", f"Failed to take screenshot. Please ensure the device is properly connected and that the application has storage permissions.\n\nError: {e}")
                
    def screen_record(self, current_device, error_callback=None):
        """Record screen"""
        if not self.check_device(error_callback):
            return
            
        save_path, _ = QFileDialog.getSaveFileName(None, "Save Video", "screenrecord.mp4", 
                                                "MP4 Files (*.mp4)")
        if save_path:
            temp_path = "/sdcard/screenrecord.mp4"
            
            if error_callback:
                error_callback("Recording", "Recording for 30 seconds...")
            
            try:
                creation_flags = 0
                if sys.platform == "win32":
                    creation_flags = subprocess.CREATE_NO_WINDOW
                subprocess.run(self.get_adb_cmd("shell", "screenrecord", "--time-limit", "30", temp_path), timeout=35, check=True, creationflags=creation_flags)
                subprocess.run(self.get_adb_cmd("pull", temp_path, save_path), timeout=30, check=True, creationflags=creation_flags)
                subprocess.run(self.get_adb_cmd("shell", "rm", temp_path), timeout=5, check=True, creationflags=creation_flags)
                if error_callback:
                    error_callback("Success", "Screen recording saved")
            except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                if error_callback:
                    error_callback("Error", f"Failed to record screen. Please ensure the device is properly connected and that the application has storage permissions.\n\nError: {e}")
                
    def enable_wifi_adb(self, current_device, error_callback=None):
        """Enable WiFi ADB"""
        if not self.check_device(error_callback):
            return
            
        try:
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW
            subprocess.run(self.get_adb_cmd("tcpip", "5555"), timeout=5, check=True, creationflags=creation_flags)
            
            # Get all network interfaces
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(self.get_adb_cmd("shell", "ip", "addr"), 
                                  capture_output=True, text=True, timeout=5, check=True, 
                                  encoding='utf-8', errors='replace', creationflags=creation_flags)
            
            # Find IP address in the output
            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/.*scope global.*wlan', result.stdout)
            
            if ip_match:
                ip = ip_match.group(1)
                if error_callback:
                    error_callback("WiFi ADB Enabled", 
                                      f"Connect using: adb connect {ip}:5555")
            else:
                if error_callback:
                    error_callback("Success", 
                                      "WiFi ADB enabled on port 5555, but could not determine IP address. Please find it manually.")
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            if error_callback:
                error_callback("Error", f"Failed to enable WiFi ADB. Make sure your device is connected and USB debugging is enabled.\n\nError: {e}")
            
    def connect_wifi_adb(self, refresh_devices_callback, error_callback=None):
        """Connect to device via WiFi"""
        ip, ok = QInputDialog.getText(None, "Connect WiFi ADB", 
                                      "Enter device IP:port (e.g., 192.168.1.100:5555):")
        if ok and ip:
            try:
                creation_flags = 0
                if sys.platform == "win32":
                    creation_flags = subprocess.CREATE_NO_WINDOW
                result = subprocess.run(self.get_adb_cmd("connect", ip), 
                                      capture_output=True, text=True, timeout=10, check=True, encoding='utf-8', errors='replace', creationflags=creation_flags)
                if error_callback:
                    error_callback("Result", result.stdout)
                refresh_devices_callback()
            except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                if error_callback:
                    error_callback("Error", f"Failed to connect: {e}")
                
    def backup_device(self, current_device, error_callback=None):
        """Backup device"""
        if not self.check_device(error_callback):
            return
            
        save_path, _ = QFileDialog.getSaveFileName(None, "Save Backup", "backup.ab", 
                                                "Backup Files (*.ab)")
        if save_path:
            cmd = self.get_adb_cmd("backup", "-all", "-f", save_path)
            if error_callback:
                error_callback("Backup", 
                                  "Please confirm backup on your device. This may take a while...")
            self.run_adb_command(cmd, lambda out: error_callback("Success", 
                                                                         "Backup completed"))
            
    def restore_device(self, current_device, error_callback=None):
        """Restore device"""
        if not self.check_device(error_callback):
            return
            
        backup_path, _ = QFileDialog.getOpenFileName(None, "Select Backup", "", 
                                                  "Backup Files (*.ab)")
        if backup_path:
            cmd = self.get_adb_cmd("restore", backup_path)
            if error_callback:
                error_callback("Restore", 
                                  "Please confirm restore on your device. This may take a while...")
            self.run_adb_command(cmd, lambda out: error_callback("Success", 
                                                                         "Restore completed"))
            
    def start_logcat(self, logcat_output, current_device, error_callback=None):
        """Start logcat monitoring"""
        if not self.check_device(error_callback):
            return

        logcat_output.clear()
        creation_flags = 0
        if sys.platform == "win32":
            creation_flags = subprocess.CREATE_NO_WINDOW
        self.logcat_process = subprocess.Popen(self.get_adb_cmd("logcat", "-v", "time"), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace', creationflags=creation_flags)
        self.logcat_timer.start(100)

    def read_logcat(self, logcat_output):
        """Read logcat output"""
        if self.logcat_process:
            try:
                line = self.logcat_process.stdout.readline()
                if line:
                    logcat_output.moveCursor(logcat_output.textCursor().End)
                    logcat_output.insertPlainText(line)
            except:
                pass

    def stop_logcat(self):
        """Stop logcat monitoring"""
        self.logcat_timer.stop()
        if self.logcat_process:
            self.logcat_process.kill()
            self.logcat_process = None

    def clear_logcat(self, logcat_output, current_device, error_callback=None):
        """Clear logcat buffer"""
        if self.check_device(error_callback):
            try:
                creation_flags = 0
                if sys.platform == "win32":
                    creation_flags = subprocess.CREATE_NO_WINDOW
                subprocess.run(self.get_adb_cmd("logcat", "-c"), check=True, creationflags=creation_flags)
                logcat_output.clear()
            except (FileNotFoundError, subprocess.CalledProcessError) as e:
                if error_callback:
                    error_callback("Error", f"Failed to clear logcat: {e}")

    def filter_logcat(self, logcat_output, search_text, log_level):
        """Filter and color logcat output"""
        search_text = search_text.lower()

        cursor = logcat_output.textCursor()
        cursor.select(QTextCursor.SelectionType.Document)
        cursor.setCharFormat(QTextCharFormat())

        if not search_text and log_level == "All":
            return

        cursor.beginEditBlock()
        while not cursor.atEnd():
            cursor.movePosition(QTextCursor.StartOfLine)
            cursor.movePosition(QTextCursor.EndOfLine, QTextCursor.KeepAnchor)
            line = cursor.selectedText()
            
            log_level_match = re.search(r' (V|D|I|W|E)/.*', line)
            if log_level_match:
                level = log_level_match.group(1)
                color = {
                    'V': QColor("gray"),
                    'D': QColor("blue"),
                    'I': QColor("green"),
                    'W': QColor("orange"),
                    'E': QColor("red"),
                }.get(level, QColor("black"))

                fmt = QTextCharFormat()
                fmt.setForeground(color)
                cursor.mergeCharFormat(fmt)

            if (search_text and search_text not in line.lower()) or \
               (log_level != "All" and log_level[0] != level):
                cursor.removeSelectedText()

            cursor.movePosition(QTextCursor.NextBlock)

        cursor.endEditBlock()
