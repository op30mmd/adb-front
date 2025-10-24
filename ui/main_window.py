import os
from pathlib import Path
from functools import partial
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTabWidget, QPushButton, QLabel, 
                             QTextEdit, QLineEdit, QTreeWidget,
                             QFileDialog, QComboBox, QSplitter, QProgressBar,
                             QMessageBox, QListWidget, QGroupBox, QTableWidget,
                             QTableWidgetItem, QHeaderView, QInputDialog, QApplication)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QColor, QPalette, QIcon

from adb_manager.adb_actions import ADBCore

class ADBManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ADB Manager")
        self.setGeometry(100, 100, 1400, 900)
        self.current_device = None
        self.device_path = "/sdcard/"
        self.logcat_timer = None
        
        self.adb_core = ADBCore()
        
        self.init_ui()
        self.adb_core.refresh_devices(self.device_combo, self.status_label)
        
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
        refresh_btn.clicked.connect(lambda: self.adb_core.refresh_devices(self.device_combo, self.status_label))
        layout.addWidget(refresh_btn)
        
        layout.addStretch()
        
        # Server controls
        start_server_btn = QPushButton("Start Server")
        start_server_btn.clicked.connect(self.adb_core.start_adb_server)
        layout.addWidget(start_server_btn)
        
        kill_server_btn = QPushButton("Kill Server")
        kill_server_btn.clicked.connect(self.adb_core.kill_adb_server)
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
        refresh_info_btn.clicked.connect(lambda: self.adb_core.load_device_info(self.device_info_table, self.current_device))
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
        refresh_battery_btn.clicked.connect(lambda: self.adb_core.load_battery_info(self.battery_table, self.current_device))
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
        self.path_edit.returnPressed.connect(lambda: self.adb_core.browse_device_path(self.path_edit.text(), self.file_tree, self.progress_bar, self.current_device))
        nav_layout.addWidget(self.path_edit)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(lambda: self.adb_core.browse_device_path(self.path_edit.text(), self.file_tree, self.progress_bar, self.current_device))
        nav_layout.addWidget(browse_btn)
        
        parent_btn = QPushButton("Parent Dir")
        parent_btn.clicked.connect(self.go_parent_directory)
        nav_layout.addWidget(parent_btn)

        home_btn = QPushButton("Home")
        home_btn.clicked.connect(self.go_home)
        nav_layout.addWidget(home_btn)
        
        layout.addLayout(nav_layout)
        
        # File list
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["Name", "Type", "Size", "Permissions"])
        self.file_tree.setColumnWidth(0, 300)
        self.file_tree.itemDoubleClicked.connect(self.on_file_double_click)
        layout.addWidget(self.file_tree)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # File operations
        ops_layout = QHBoxLayout()
        
        pull_btn = QPushButton("Pull (Download)")
        pull_btn.clicked.connect(lambda:         self.adb_core.pull_file(self.file_tree.currentItem(), self.device_path, self.current_device, self.show_message))
        ops_layout.addWidget(pull_btn)
        
        push_btn = QPushButton("Push (Upload)")
        push_btn.clicked.connect(lambda: self.adb_core.push_file(self.device_path, self.current_device, self.browse_device_path, self.show_message))
        ops_layout.addWidget(push_btn)
        
        delete_btn = QPushButton("Delete")
        delete_btn.clicked.connect(lambda: self.adb_core.delete_file(self.file_tree.currentItem(), self.device_path, self.current_device, self.browse_device_path, self.show_message))
        ops_layout.addWidget(delete_btn)
        
        mkdir_btn = QPushButton("New Folder")
        mkdir_btn.clicked.connect(lambda: self.adb_core.create_directory(self.device_path, self.current_device, self.browse_device_path, self.show_message))
        ops_layout.addWidget(mkdir_btn)
        
        ops_layout.addStretch()
        layout.addLayout(ops_layout)
        
        return widget
        
    def create_shell_tab(self):
        """Create shell terminal tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Shell output
        self.shell_output = QTextEdit()
        self.shell_output.setReadOnly(True)
        self.shell_output.setFont(QFont("Consolas", 10))
        layout.addWidget(self.shell_output)
        
        # Command input
        cmd_layout = QHBoxLayout()
        cmd_layout.addWidget(QLabel("Command:"))
        self.shell_input = QLineEdit()
        self.shell_input.returnPressed.connect(lambda: self.adb_core.execute_shell_command(self.shell_input.text(), self.shell_output, self.current_device, self.show_message))
        self.shell_input.setPlaceholderText("Enter ADB shell command...")
        cmd_layout.addWidget(self.shell_input)
        
        exec_btn = QPushButton("Execute")
        exec_btn.clicked.connect(lambda: self.adb_core.execute_shell_command(self.shell_input.text(), self.shell_output, self.current_device, self.show_message))
        cmd_layout.addWidget(exec_btn)

        stop_btn = QPushButton("Stop")
        stop_btn.clicked.connect(self.adb_core.send_ctrl_c_to_shell)
        cmd_layout.addWidget(stop_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.shell_output.clear)
        cmd_layout.addWidget(clear_btn)
        
        layout.addLayout(cmd_layout)
        
        return widget
        
    def create_apps_tab(self):
        """Create apps management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # App list
        list_layout = QHBoxLayout()
        
        all_apps_btn = QPushButton("List All Apps")
        all_apps_btn.clicked.connect(lambda: self.adb_core.list_packages("all", self.apps_list, self.current_device, self.show_message))
        list_layout.addWidget(all_apps_btn)
        
        system_apps_btn = QPushButton("System Apps")
        system_apps_btn.clicked.connect(lambda: self.adb_core.list_packages("system", self.apps_list, self.current_device, self.show_message))
        list_layout.addWidget(system_apps_btn)
        
        user_apps_btn = QPushButton("User Apps")
        user_apps_btn.clicked.connect(lambda: self.adb_core.list_packages("3rd", self.apps_list, self.current_device, self.show_message))
        list_layout.addWidget(user_apps_btn)
        
        list_layout.addStretch()
        layout.addLayout(list_layout)
        
        # Apps list widget
        self.apps_list = QListWidget()
        layout.addWidget(self.apps_list)
        
        # App operations
        ops_layout = QHBoxLayout()
        
        install_btn = QPushButton("Install APK")
        install_btn.clicked.connect(lambda: self.adb_core.install_apk(self.current_device, self.show_message))
        ops_layout.addWidget(install_btn)
        
        uninstall_btn = QPushButton("Uninstall")
        uninstall_btn.clicked.connect(lambda: self.adb_core.uninstall_app(self.apps_list.currentItem(), self.current_device, self.list_packages, self.show_message))
        ops_layout.addWidget(uninstall_btn)
        
        clear_data_btn = QPushButton("Clear Data")
        clear_data_btn.clicked.connect(lambda: self.adb_core.clear_app_data(self.apps_list.currentItem(), self.current_device, self.show_message))
        ops_layout.addWidget(clear_data_btn)
        
        force_stop_btn = QPushButton("Force Stop")
        force_stop_btn.clicked.connect(lambda: self.adb_core.force_stop_app(self.apps_list.currentItem(), self.current_device, self.show_message))
        ops_layout.addWidget(force_stop_btn)
        
        ops_layout.addStretch()
        layout.addLayout(ops_layout)
        
        return widget
        
    def create_tools_tab(self):
        """Create tools tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Screen tools
        screen_group = QGroupBox("Screen Tools")
        screen_layout = QVBoxLayout()
        
        screen_btns = QHBoxLayout()
        screenshot_btn = QPushButton("Screenshot")
        screenshot_btn.clicked.connect(lambda: self.adb_core.take_screenshot(self.current_device, self.show_message))
        screen_btns.addWidget(screenshot_btn)
        
        screenrecord_btn = QPushButton("Screen Record (30s)")
        screenrecord_btn.clicked.connect(lambda: self.adb_core.screen_record(self.current_device, self.show_message))
        screen_btns.addWidget(screenrecord_btn)
        
        screen_btns.addStretch()
        screen_layout.addLayout(screen_btns)
        screen_group.setLayout(screen_layout)
        layout.addWidget(screen_group)
        
        # Device control
        control_group = QGroupBox("Device Control")
        control_layout = QVBoxLayout()
        
        control_btns = QHBoxLayout()
        reboot_btn = QPushButton("Reboot")
        reboot_btn.clicked.connect(lambda: self.adb_core.run_adb_command(self.adb_core.get_adb_cmd("reboot"), error_callback=self.show_message))
        control_btns.addWidget(reboot_btn)
        
        recovery_btn = QPushButton("Reboot Recovery")
        recovery_btn.clicked.connect(lambda: self.adb_core.run_adb_command(self.adb_core.get_adb_cmd("reboot", "recovery"), error_callback=self.show_message))
        control_btns.addWidget(recovery_btn)
        
        bootloader_btn = QPushButton("Reboot Bootloader")
        bootloader_btn.clicked.connect(lambda: self.adb_core.run_adb_command(self.adb_core.get_adb_cmd("reboot", "bootloader"), error_callback=self.show_message))
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
        wifi_btn.clicked.connect(lambda:         self.adb_core.enable_wifi_adb(self.current_device, self.show_message))
        network_btns.addWidget(wifi_btn)
        
        connect_btn = QPushButton("Connect to IP")
        connect_btn.clicked.connect(lambda: self.adb_core.connect_wifi_adb(self.refresh_devices, self.show_message))
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
        backup_btn.clicked.connect(lambda: self.adb_core.backup_device(self.current_device, self.show_message))
        backup_btns.addWidget(backup_btn)
        
        restore_btn = QPushButton("Restore")
        restore_btn.clicked.connect(lambda: self.adb_core.restore_device(self.current_device, self.show_message))
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
        start_log_btn.clicked.connect(lambda: self.adb_core.start_logcat(self.logcat_output, self.current_device, self.show_message))
        controls.addWidget(start_log_btn)
        
        stop_log_btn = QPushButton("Stop Logcat")
        stop_log_btn.clicked.connect(self.adb_core.stop_logcat)
        controls.addWidget(stop_log_btn)
        
        clear_log_btn = QPushButton("Clear")
        clear_log_btn.clicked.connect(lambda: self.adb_core.clear_logcat(self.logcat_output, self.current_device, self.show_message))
        controls.addWidget(clear_log_btn)
        
        controls.addStretch()

        # Filter
        controls.addWidget(QLabel("Filter:"))
        self.logcat_filter_combo = QComboBox()
        self.logcat_filter_combo.addItems(["All", "Verbose", "Debug", "Info", "Warning", "Error"])
        self.logcat_filter_combo.currentTextChanged.connect(lambda: self.adb_core.filter_logcat(self.logcat_output, self.logcat_search_input.text(), self.logcat_filter_combo.currentText()))
        controls.addWidget(self.logcat_filter_combo)

        # Search
        controls.addWidget(QLabel("Search:"))
        self.logcat_search_input = QLineEdit()
        self.logcat_search_input.setPlaceholderText("Search logs...")
        self.logcat_search_input.textChanged.connect(lambda: self.adb_core.filter_logcat(self.logcat_output, self.logcat_search_input.text(), self.logcat_filter_combo.currentText()))
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
        self.adb_core.on_device_changed(device, self.status_label, self.device_info_table, self.battery_table, self.path_edit, self.file_tree, self.progress_bar, self.apps_list)

    def go_parent_directory(self):
        path = Path(self.path_edit.text())
        parent = str(path.parent)
        if parent != self.path_edit.text():
            self.path_edit.setText(parent)
            self.adb_core.browse_device_path(parent, self.file_tree, self.progress_bar, self.current_device)

    def go_home(self):
        self.path_edit.setText("/sdcard/")
        self.adb_core.browse_device_path("/sdcard/", self.file_tree, self.progress_bar, self.current_device)

    def on_file_double_click(self, item):
        name = item.text(0)
        file_type = item.text(1)
        
        if file_type == "Directory":
            new_path = os.path.join(self.path_edit.text(), name)
            self.path_edit.setText(new_path)
            self.adb_core.browse_device_path(new_path, self.file_tree, self.progress_bar, self.current_device)

    def show_message(self, title, message):
        QMessageBox.information(self, title, message)

    def cleanup(self):
        """Clean up resources before exiting"""
        self.adb_core.stop_interactive_shell()

    def closeEvent(self, event):
        self.cleanup()
        QApplication.quit()
        event.accept()