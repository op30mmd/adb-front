import os
import platform
from pathlib import Path
import re
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTabWidget, QPushButton, QLabel, 
                             QTextEdit, QLineEdit,
                             QFileDialog, QComboBox, QSplitter, QProgressBar,
                             QMessageBox, QListWidget, QGroupBox, QTableWidget,
                             QTableWidgetItem, QHeaderView, QInputDialog, QApplication,
                             QStyle)
from PyQt6.QtCore import Qt, QTimer, QEvent
from PyQt6.QtGui import QFont, QColor, QPalette, QIcon, QTextCharFormat, QTextCursor, QPainter, QPixmap
from PyQt6.QtSvg import QSvgRenderer

from termqt import Terminal
if platform.system() == "Windows":
    from termqt import TerminalWinptyIO as TerminalIO
else:
    from termqt import TerminalPOSIXExecIO as TerminalIO

import platform

from adb_manager.adb_actions import ADBCore

class ADBManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowIcon(QIcon(os.path.join(os.path.dirname(__file__), "icon.png")))
        self.setWindowTitle("ADB Manager")
        self.setGeometry(100, 100, 1400, 900)
        self.current_device = None
        self.device_path = "/sdcard/"
        self.logcat_timer = None
        self.terminal_io = None
        
        self.adb_core = ADBCore()
        
        self.init_ui()

        # Defer the initial device scan to improve startup time
        QTimer.singleShot(100, self.refresh_devices)

    def get_icon(self, name):
        """Get icon based on platform"""
        if platform.system() == "Windows":
            icon_path = os.path.join(os.path.dirname(__file__), "icons", "fluent", f"{name}.svg")

            renderer = QSvgRenderer(icon_path)
            pixmap = QPixmap(renderer.defaultSize())
            pixmap.fill(Qt.GlobalColor.transparent)

            painter = QPainter(pixmap)
            renderer.render(painter)

            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
            painter.fillRect(pixmap.rect(), self.palette().color(QPalette.ColorRole.Text))
            painter.end()

            return QIcon(pixmap)
        else:
            return QIcon.fromTheme(name)
        
    def init_ui(self):
        """Initialize the user interface"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Header with device selection
        header = self.create_header()
        layout.addLayout(header)
        
        # Tab widget for different features
        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_device_info_tab(), "Device Info")
        self.tabs.addTab(self.create_file_manager_tab(), "File Manager")
        self.tabs.addTab(self.create_shell_tab(), "Shell")
        self.tabs.addTab(self.create_apps_tab(), "Apps")
        self.tabs.addTab(self.create_tools_tab(), "Tools")
        self.tabs.addTab(self.create_logcat_tab(), "Logcat")
        
        layout.addWidget(self.tabs)

        # Status bar
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
        
    def create_header(self):
        """Create header with device selector and controls"""
        layout = QHBoxLayout()
        
        # Device selector
        layout.addWidget(QLabel("Connected Device:"))
        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(300)
        self.device_combo.currentTextChanged.connect(self.on_device_changed)
        layout.addWidget(self.device_combo)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh Devices")
        refresh_btn.setIcon(self.get_icon("view-refresh"))
        refresh_btn.clicked.connect(self.refresh_devices)
        layout.addWidget(refresh_btn)
        
        layout.addStretch()
        
        # Server controls
        start_server_btn = QPushButton("Start Server")
        start_server_btn.setIcon(self.get_icon("media-playback-start"))
        start_server_btn.clicked.connect(self.start_adb_server)
        layout.addWidget(start_server_btn)
        
        kill_server_btn = QPushButton("Kill Server")
        kill_server_btn.setIcon(self.get_icon("process-stop"))
        kill_server_btn.clicked.connect(self.kill_adb_server)
        layout.addWidget(kill_server_btn)
        
        return layout
        
    def create_device_info_tab(self):
        """Create device information tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Device info display
        info_group = QGroupBox("Device Information")
        info_layout = QVBoxLayout()
        
        self.device_info_table = QTableWidget()
        self.device_info_table.setColumnCount(2)
        self.device_info_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.device_info_table.horizontalHeader().setStretchLastSection(True)
        info_layout.addWidget(self.device_info_table)
        
        refresh_info_btn = QPushButton("Refresh Info")
        refresh_info_btn.setIcon(self.get_icon("view-refresh"))
        refresh_info_btn.clicked.connect(self.load_device_info)
        info_layout.addWidget(refresh_info_btn)
        
        info_group.setLayout(info_layout)
        splitter.addWidget(info_group)
        
        # Battery info
        battery_group = QGroupBox("Battery Status")
        battery_layout = QVBoxLayout()
        
        self.battery_table = QTableWidget()
        self.battery_table.setColumnCount(2)
        self.battery_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.battery_table.horizontalHeader().setStretchLastSection(True)
        battery_layout.addWidget(self.battery_table)
        
        refresh_battery_btn = QPushButton("Refresh Battery")
        refresh_battery_btn.setIcon(self.get_icon("view-refresh"))
        refresh_battery_btn.clicked.connect(self.load_battery_info)
        battery_layout.addWidget(refresh_battery_btn)
        
        battery_group.setLayout(battery_layout)
        splitter.addWidget(battery_group)
        
        layout.addWidget(splitter)
        return widget
        
    def create_file_manager_tab(self):
        """Create file manager tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Path navigation
        nav_layout = QHBoxLayout()
        nav_layout.addWidget(QLabel("Path:"))
        self.path_edit = QLineEdit("/sdcard/")
        self.path_edit.returnPressed.connect(self.browse_device_path)
        nav_layout.addWidget(self.path_edit)
        
        browse_btn = QPushButton("Browse")
        browse_btn.setIcon(self.get_icon("document-open"))
        browse_btn.clicked.connect(self.browse_device_path)
        nav_layout.addWidget(browse_btn)
        
        parent_btn = QPushButton("Parent Dir")
        parent_btn.setIcon(self.get_icon("go-up"))
        parent_btn.clicked.connect(self.go_parent_directory)
        nav_layout.addWidget(parent_btn)

        home_btn = QPushButton("Home")
        home_btn.setIcon(self.get_icon("go-home"))
        home_btn.clicked.connect(self.go_home)
        nav_layout.addWidget(home_btn)
        
        layout.addLayout(nav_layout)
        
        # File list
        self.file_table = QTableWidget()
        self.file_table.setColumnCount(4)
        self.file_table.setHorizontalHeaderLabels(["Name", "Type", "Size", "Permissions"])
        self.file_table.setColumnWidth(0, 300)
        self.file_table.horizontalHeader().setStretchLastSection(True)
        self.file_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.file_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.file_table.itemDoubleClicked.connect(self.on_file_double_click)
        layout.addWidget(self.file_table)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # File operations
        ops_layout = QHBoxLayout()
        
        pull_btn = QPushButton("Pull (Download)")
        pull_btn.setIcon(self.get_icon("arrow-down"))
        pull_btn.clicked.connect(self.pull_file)
        ops_layout.addWidget(pull_btn)
        
        push_btn = QPushButton("Push (Upload)")
        push_btn.setIcon(self.get_icon("arrow-up"))
        push_btn.clicked.connect(self.push_file)
        ops_layout.addWidget(push_btn)
        
        delete_btn = QPushButton("Delete")
        delete_btn.setIcon(self.get_icon("edit-delete"))
        delete_btn.clicked.connect(self.delete_file)
        ops_layout.addWidget(delete_btn)
        
        mkdir_btn = QPushButton("New Folder")
        mkdir_btn.setIcon(self.get_icon("folder-new"))
        mkdir_btn.clicked.connect(self.create_directory)
        ops_layout.addWidget(mkdir_btn)
        
        ops_layout.addStretch()
        layout.addLayout(ops_layout)
        
        return widget

    def create_shell_tab(self):
        """Create shell terminal tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.shell_widget = Terminal(800, 600)
        layout.addWidget(self.shell_widget)
        
        return widget
        
    def create_apps_tab(self):
        """Create apps management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # App list
        list_layout = QHBoxLayout()
        
        all_apps_btn = QPushButton("List All Apps")
        all_apps_btn.setIcon(self.get_icon("view-list"))
        all_apps_btn.clicked.connect(lambda: self.list_packages("all"))
        list_layout.addWidget(all_apps_btn)
        
        system_apps_btn = QPushButton("System Apps")
        system_apps_btn.setIcon(self.get_icon("system-software-install"))
        system_apps_btn.clicked.connect(lambda: self.list_packages("system"))
        list_layout.addWidget(system_apps_btn)
        
        user_apps_btn = QPushButton("User Apps")
        user_apps_btn.setIcon(self.get_icon("user-desktop"))
        user_apps_btn.clicked.connect(lambda: self.list_packages("3rd"))
        list_layout.addWidget(user_apps_btn)
        
        list_layout.addStretch()
        layout.addLayout(list_layout)
        
        # Apps list widget
        self.apps_list = QListWidget()
        layout.addWidget(self.apps_list)
        
        # App operations
        ops_layout = QHBoxLayout()
        
        install_btn = QPushButton("Install APK")
        install_btn.setIcon(self.get_icon("document-new"))
        install_btn.clicked.connect(self.install_apk)
        ops_layout.addWidget(install_btn)
        
        uninstall_btn = QPushButton("Uninstall")
        uninstall_btn.setIcon(self.get_icon("edit-delete"))
        uninstall_btn.clicked.connect(self.uninstall_app)
        ops_layout.addWidget(uninstall_btn)
        
        clear_data_btn = QPushButton("Clear Data")
        clear_data_btn.setIcon(self.get_icon("edit-clear"))
        clear_data_btn.clicked.connect(self.clear_app_data)
        ops_layout.addWidget(clear_data_btn)
        
        force_stop_btn = QPushButton("Force Stop")
        force_stop_btn.setIcon(self.get_icon("process-stop"))
        force_stop_btn.clicked.connect(self.force_stop_app)
        ops_layout.addWidget(force_stop_btn)
        
        ops_layout.addStretch()
        layout.addLayout(ops_layout)
        
        return widget
        
    def create_tools_tab(self):
        """Create tools tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Screenshot tools
        screenshot_group = QGroupBox("Screenshot")
        screenshot_layout = QVBoxLayout()
        screenshot_btn = QPushButton("Take Screenshot")
        screenshot_btn.setIcon(self.get_icon("media-record"))
        screenshot_btn.clicked.connect(self.take_screenshot)
        screenshot_layout.addWidget(screenshot_btn)
        screenshot_group.setLayout(screenshot_layout)
        layout.addWidget(screenshot_group)

        # Screenrecord tools
        screenrecord_group = QGroupBox("Screen Record")
        screenrecord_layout = QVBoxLayout()
        
        screenrecord_btn = QPushButton("Start Recording")
        screenrecord_btn.setIcon(self.get_icon("media-record"))
        screenrecord_btn.clicked.connect(self.screen_record)
        screenrecord_layout.addWidget(screenrecord_btn)
        
        # Add screen record options
        record_options_layout = QHBoxLayout()
        record_options_layout.addWidget(QLabel("Resolution (e.g., 1280x720):"))
        self.resolution_edit = QLineEdit()
        self.resolution_edit.setPlaceholderText("Default")
        record_options_layout.addWidget(self.resolution_edit)

        record_options_layout.addWidget(QLabel("Bitrate (e.g., 4M):"))
        self.bitrate_edit = QLineEdit()
        self.bitrate_edit.setPlaceholderText("Default")
        record_options_layout.addWidget(self.bitrate_edit)

        record_options_layout.addWidget(QLabel("Time Limit (s):"))
        self.time_limit_edit = QLineEdit("30")
        record_options_layout.addWidget(self.time_limit_edit)
        screenrecord_layout.addLayout(record_options_layout)
        screenrecord_group.setLayout(screenrecord_layout)
        layout.addWidget(screenrecord_group)
        
        # Device control
        control_group = QGroupBox("Device Control")
        control_layout = QVBoxLayout()
        
        control_btns = QHBoxLayout()
        reboot_btn = QPushButton("Reboot")
        reboot_btn.setIcon(self.get_icon("system-reboot"))
        reboot_btn.clicked.connect(lambda: self.adb_core.run_adb_command(self.adb_core.get_adb_cmd("reboot")))
        control_btns.addWidget(reboot_btn)
        
        recovery_btn = QPushButton("Reboot Recovery")
        recovery_btn.setIcon(self.get_icon("system-reboot"))
        recovery_btn.clicked.connect(lambda: self.adb_core.run_adb_command(self.adb_core.get_adb_cmd("reboot", "recovery")))
        control_btns.addWidget(recovery_btn)
        
        bootloader_btn = QPushButton("Reboot Bootloader")
        bootloader_btn.setIcon(self.get_icon("system-reboot"))
        bootloader_btn.clicked.connect(lambda: self.adb_core.run_adb_command(self.adb_core.get_adb_cmd("reboot", "bootloader")))
        control_btns.addWidget(bootloader_btn)
        
        control_btns.addStretch()
        control_layout.addLayout(control_btns)
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Network tools
        network_group = QGroupBox("Network & Connection")
        network_layout = QVBoxLayout()
        
        network_btns = QHBoxLayout()
        wifi_btn = QPushButton("Enable WiFi ADB")
        wifi_btn.setIcon(self.get_icon("network-wireless"))
        wifi_btn.clicked.connect(self.enable_wifi_adb)
        network_btns.addWidget(wifi_btn)
        
        connect_btn = QPushButton("Connect to IP")
        connect_btn.setIcon(self.get_icon("network-wired"))
        connect_btn.clicked.connect(self.connect_wifi_adb)
        network_btns.addWidget(connect_btn)
        
        network_btns.addStretch()
        network_layout.addLayout(network_btns)
        network_group.setLayout(network_layout)
        layout.addWidget(network_group)
        
        # Backup & Restore
        backup_group = QGroupBox("Backup & Restore")
        backup_layout = QVBoxLayout()
        
        backup_btns = QHBoxLayout()
        backup_btn = QPushButton("Backup")
        backup_btn.setIcon(self.get_icon("document-save"))
        backup_btn.clicked.connect(self.backup_device)
        backup_btns.addWidget(backup_btn)
        
        restore_btn = QPushButton("Restore")
        restore_btn.setIcon(self.get_icon("document-open"))
        restore_btn.clicked.connect(self.restore_device)
        backup_btns.addWidget(restore_btn)
        
        backup_btns.addStretch()
        backup_layout.addLayout(backup_btns)
        backup_group.setLayout(backup_layout)
        layout.addWidget(backup_group)
        
        layout.addStretch()
        return widget
        
    def create_logcat_tab(self):
        """Create logcat viewer tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Logcat controls
        controls = QHBoxLayout()
        
        start_log_btn = QPushButton("Start Logcat")
        start_log_btn.setIcon(self.get_icon("media-playback-start"))
        start_log_btn.clicked.connect(self.start_logcat)
        controls.addWidget(start_log_btn)
        
        stop_log_btn = QPushButton("Stop Logcat")
        stop_log_btn.setIcon(self.get_icon("media-playback-stop"))
        stop_log_btn.clicked.connect(self.stop_logcat)
        controls.addWidget(stop_log_btn)
        
        clear_log_btn = QPushButton("Clear")
        clear_log_btn.setIcon(self.get_icon("edit-clear"))
        clear_log_btn.clicked.connect(self.clear_logcat)
        controls.addWidget(clear_log_btn)
        
        controls.addStretch()

        # Filter
        controls.addWidget(QLabel("Filter:"))
        self.logcat_filter_combo = QComboBox()
        self.logcat_filter_combo.addItems(["All", "Verbose", "Debug", "Info", "Warning", "Error"])
        self.logcat_filter_combo.currentTextChanged.connect(self.filter_logcat)
        controls.addWidget(self.logcat_filter_combo)

        # Search
        controls.addWidget(QLabel("Search:"))
        self.logcat_search_input = QLineEdit()
        self.logcat_search_input.setPlaceholderText("Search logs...")
        self.logcat_search_input.textChanged.connect(self.filter_logcat)
        controls.addWidget(self.logcat_search_input)

        layout.addLayout(controls)
        
        # Logcat output
        self.logcat_output = QTextEdit()
        self.logcat_output.setReadOnly(True)
        self.logcat_output.setFont(QFont("Consolas", 9))
        layout.addWidget(self.logcat_output)
        
        return widget

    def on_device_changed(self, device):
        self.current_device = device
        self.adb_core.on_device_changed(device)

        if self.terminal_io:
            self.terminal_io.terminate()
            self.terminal_io = None

        if self.current_device:
            self.status_label.setText(f"Connected to: {self.current_device}")
            self.load_device_info()
            self.load_battery_info()
            self.browse_device_path()
            self.list_packages("all")
            self.setup_shell_for_device(self.current_device)
        else:
            self.status_label.setText("No devices connected")

    def setup_shell_for_device(self, device_serial):
        try:
            adb_path = self.adb_core.adb_path

            # Use "shell" without "-tt" for Windows as it can cause issues with some environments
            cmd = [adb_path, "-s", device_serial, "shell"]
            if platform.system() != "Windows":
                cmd.append("-tt")

            self.terminal_io = TerminalIO(
                self.shell_widget.row_len,
                self.shell_widget.col_len,
                cmd
            )

            if platform.system() == "Windows":
                self.shell_widget.enable_auto_wrap(False)

            self.terminal_io.stdout_callback = self.shell_widget.stdout
            self.shell_widget.stdin_callback = self.terminal_io.write
            self.shell_widget.resize_callback = self.terminal_io.resize
            self.terminal_io.spawn()
        except Exception as e:
            self.show_error(f"Failed to start ADB shell: {e}")

    def go_parent_directory(self):
        path = Path(self.path_edit.text())
        parent = str(path.parent)
        if parent != self.path_edit.text():
            self.path_edit.setText(parent)
            self.browse_device_path()

    def go_home(self):
        self.path_edit.setText("/sdcard/")
        self.browse_device_path()

    def on_file_double_click(self, item):
        if item is None:
            return
        
        row = item.row()
        name_item = self.file_table.item(row, 0)
        type_item = self.file_table.item(row, 1)

        if name_item and type_item:
            name = name_item.text()
            file_type = type_item.text()

            if file_type == "Directory":
                path = self.path_edit.text()
                # Prevent multiple slashes when navigating
                if not path.endswith('/'):
                    path += '/'
                new_path = path + name
                self.path_edit.setText(new_path)
                self.browse_device_path()

    def show_message(self, title, message):
        QMessageBox.information(self, title, message)

    def show_error(self, message):
        QMessageBox.critical(self, "Error", message)

    def cleanup(self):
        """Clean up resources before exiting"""
        self.adb_core.cleanup()
        if self.terminal_io:
            self.terminal_io.terminate()

    def closeEvent(self, event):
        self.cleanup()
        QApplication.quit()
        event.accept()

    def refresh_devices(self):
        try:
            devices = self.adb_core.refresh_devices()
            self.device_combo.clear()
            self.device_combo.addItems(devices)
            if devices:
                self.current_device = devices[0]
                self.status_label.setText(f"Connected to: {self.current_device}")
            else:
                self.current_device = None
                self.status_label.setText("No devices connected")
        except RuntimeError as e:
            self.show_error(str(e))

    def start_adb_server(self):
        try:
            self.adb_core.start_adb_server()
            self.refresh_devices()
        except RuntimeError as e:
            self.show_error(str(e))

    def kill_adb_server(self):
        try:
            self.adb_core.kill_adb_server()
            self.device_combo.clear()
            self.current_device = None
            self.status_label.setText("No devices connected")
        except RuntimeError as e:
            self.show_error(str(e))

    def load_device_info(self):
        try:
            info = self.adb_core.load_device_info()
            self.device_info_table.setRowCount(0)
            if info:
                self.device_info_table.setRowCount(len(info))
                for row, (label, value) in enumerate(info):
                    self.device_info_table.setItem(row, 0, QTableWidgetItem(label))
                    self.device_info_table.setItem(row, 1, QTableWidgetItem(value))
        except RuntimeError as e:
            self.show_error(str(e))

    def load_battery_info(self):
        try:
            battery_info = self.adb_core.load_battery_info()
            self.battery_table.setRowCount(0)
            if battery_info:
                row = 0
                for key, value in battery_info.items():
                    self.battery_table.insertRow(row)
                    self.battery_table.setItem(row, 0, QTableWidgetItem(key.replace("_", " ").title()))

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

                    self.battery_table.setItem(row, 1, QTableWidgetItem(str(value)))
                    row += 1
        except RuntimeError as e:
            self.show_error(str(e))

    def browse_device_path(self):
        try:
            path = self.path_edit.text()
            files = self.adb_core.browse_device_path(path)
            self.file_table.setRowCount(0)
            if files:
                self.file_table.setRowCount(len(files))
                for i, f in enumerate(files):
                    name_item = QTableWidgetItem(f["name"])

                    if f["type"] == "Directory":
                        name_item.setIcon(self.get_icon("folder"))
                    else:
                        name_item.setIcon(self.get_icon("document"))

                    self.file_table.setItem(i, 0, name_item)
                    self.file_table.setItem(i, 1, QTableWidgetItem(f["type"]))
                    self.file_table.setItem(i, 2, QTableWidgetItem(f["size"]))
                    self.file_table.setItem(i, 3, QTableWidgetItem(f["permissions"]))
        except RuntimeError as e:
            self.show_error(str(e))

    def pull_file(self):
        selected_items = self.file_table.selectedItems()
        if not selected_items:
            self.show_message("Warning", "Please select a file")
            return

        row = self.file_table.currentRow()
        filename = self.file_table.item(row, 0).text()
        source = f"{self.path_edit.text()}/{filename}".replace('//', '/')

        dest, _ = QFileDialog.getSaveFileName(None, "Save File", filename)
        if dest:
            try:
                self.adb_core.pull_file(source, dest, lambda: self.show_message("Success", "File pulled successfully"))
            except RuntimeError as e:
                self.show_error(str(e))

    def push_file(self):
        source, _ = QFileDialog.getOpenFileName(None, "Select File")
        if source:
            dest = f"{self.path_edit.text()}/{os.path.basename(source)}".replace('//', '/')
            try:
                self.adb_core.push_file(source, dest, self.browse_device_path)
                self.show_message("Success", "File pushed successfully")
            except RuntimeError as e:
                self.show_error(str(e))

    def delete_file(self):
        selected_items = self.file_table.selectedItems()
        if not selected_items:
            self.show_message("Warning", "Please select a file")
            return

        row = self.file_table.currentRow()
        filename = self.file_table.item(row, 0).text()

        reply = QMessageBox.question(None, "Confirm", f"Delete {filename}?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            path = f"{self.path_edit.text()}/{filename}".replace('//', '/')
            try:
                self.adb_core.delete_file(path, self.browse_device_path)
                self.show_message("Success", "File deleted successfully")
            except RuntimeError as e:
                self.show_error(str(e))

    def create_directory(self):
        name, ok = QInputDialog.getText(None, "New Folder", "Folder name:")
        if ok and name:
            path = f"{self.path_edit.text()}/{name}".replace('//', '/')
            try:
                self.adb_core.create_directory(path, self.browse_device_path)
                self.show_message("Success", "Folder created successfully")
            except RuntimeError as e:
                self.show_error(str(e))

    def list_packages(self, pkg_type):
        try:
            packages = self.adb_core.list_packages(pkg_type)
            self.apps_list.clear()
            self.apps_list.addItems(packages)
        except RuntimeError as e:
            self.show_error(str(e))

    def install_apk(self):
        apk_path, _ = QFileDialog.getOpenFileName(None, "Select APK", "", "APK Files (*.apk)")
        if apk_path:
            try:
                self.adb_core.install_apk(apk_path, lambda: self.list_packages("3rd"))
                self.show_message("Success", "APK installed")
            except RuntimeError as e:
                self.show_error(str(e))

    def uninstall_app(self):
        selected_item = self.apps_list.currentItem()
        if not selected_item:
            self.show_message("Warning", "Please select an app")
            return

        package = selected_item.text()
        reply = QMessageBox.question(None, "Confirm", f"Uninstall {package}?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.adb_core.uninstall_app(package, lambda: self.list_packages("3rd"))
                self.show_message("Success", "App uninstalled")
            except RuntimeError as e:
                self.show_error(str(e))

    def clear_app_data(self):
        selected_item = self.apps_list.currentItem()
        if not selected_item:
            self.show_message("Warning", "Please select an app")
            return

        package = selected_item.text()
        try:
            self.adb_core.clear_app_data(package)
            self.show_message("Success", "App data cleared")
        except RuntimeError as e:
            self.show_error(str(e))

    def force_stop_app(self):
        selected_item = self.apps_list.currentItem()
        if not selected_item:
            self.show_message("Warning", "Please select an app")
            return

        package = selected_item.text()
        try:
            self.adb_core.force_stop_app(package)
            self.show_message("Success", "App force stopped")
        except RuntimeError as e:
            self.show_error(str(e))

    def take_screenshot(self):
        save_path, _ = QFileDialog.getSaveFileName(None, "Save Screenshot", "screenshot.png",
                                                "PNG Files (*.png)")
        if save_path:
            try:
                if self.adb_core.take_screenshot(save_path):
                    self.show_message("Success", "Screenshot saved")
                else:
                    self.show_error("Failed to take screenshot. Please ensure the device is properly connected and that the application has storage permissions.")
            except RuntimeError as e:
                self.show_error(str(e))

    def screen_record(self):
        resolution = self.resolution_edit.text()
        bitrate = self.bitrate_edit.text()
        time_limit = self.time_limit_edit.text()

        save_path, _ = QFileDialog.getSaveFileName(None, "Save Video", "screenrecord.mp4",
                                                "MP4 Files (*.mp4)")
        if save_path:
            try:
                time_limit_int = int(time_limit)
                self.show_message("Recording", f"Recording for {time_limit} seconds...")
                if self.adb_core.screen_record(save_path, resolution, bitrate, time_limit):
                    self.show_message("Success", "Screen recording saved")
                else:
                    self.show_error("Failed to record screen. Please ensure the device is properly connected and that the application has storage permissions.")
            except ValueError:
                self.show_error("Invalid time limit. Please enter a valid number.")
            except RuntimeError as e:
                self.show_error(str(e))

    def enable_wifi_adb(self):
        try:
            result = self.adb_core.enable_wifi_adb()
            if result == "Enabled":
                self.show_message("Success", "WiFi ADB enabled on port 5555, but could not determine IP address. Please find it manually.")
            else:
                self.show_message("WiFi ADB Enabled", f"Connect using: adb connect {result}:5555")
        except RuntimeError as e:
            self.show_error(str(e))

    def connect_wifi_adb(self):
        ip, ok = QInputDialog.getText(None, "Connect WiFi ADB",
                                      "Enter device IP:port (e.g., 192.168.1.100:5555):")
        if ok and ip:
            try:
                result = self.adb_core.connect_wifi_adb(ip)
                self.show_message("Result", result)
                self.refresh_devices()
            except RuntimeError as e:
                self.show_error(str(e))

    def backup_device(self):
        save_path, _ = QFileDialog.getSaveFileName(None, "Save Backup", "backup.ab",
                                                "Backup Files (*.ab)")
        if save_path:
            self.show_message("Backup", "Please confirm backup on your device. This may take a while...")
            try:
                self.adb_core.backup_device(save_path, lambda: self.show_message("Success", "Backup completed"))
            except RuntimeError as e:
                self.show_error(str(e))

    def restore_device(self):
        backup_path, _ = QFileDialog.getOpenFileName(None, "Select Backup", "",
                                                  "Backup Files (*.ab)")
        if backup_path:
            self.show_message("Restore", "Please confirm restore on your device. This may take a while...")
            try:
                self.adb_core.restore_device(backup_path, lambda: self.show_message("Success", "Restore completed"))
            except RuntimeError as e:
                self.show_error(str(e))

    def start_logcat(self):
        self.logcat_output.clear()
        try:
            self.adb_core.start_logcat_thread(self.handle_logcat_line)
        except RuntimeError as e:
            self.show_error(str(e))

    def handle_logcat_line(self, line):
        self.logcat_output.moveCursor(self.logcat_output.textCursor().End)
        self.logcat_output.insertPlainText(line + '\n')

    def stop_logcat(self):
        self.adb_core.stop_logcat_thread()

    def clear_logcat(self):
        try:
            self.adb_core.clear_logcat()
            self.logcat_output.clear()
        except RuntimeError as e:
            self.show_error(str(e))

    def filter_logcat(self):
        """Filter and color logcat output"""
        search_text = self.logcat_search_input.text().lower()
        log_level = self.logcat_filter_combo.currentText()

        cursor = self.logcat_output.textCursor()
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