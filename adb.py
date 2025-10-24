#!/usr/bin/env python

import sys
import multiprocessing
import os
import logging
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import QLockFile, QDir

from ui.main_window import ADBManager

def setup_logging():
    """Configure logging to a file."""
    if hasattr(sys, '_MEIPASS'):
        # In a PyInstaller bundle
        app_dir = os.path.dirname(sys.executable)
    else:
        # In a normal Python environment
        app_dir = os.path.abspath(".")

    log_file = os.path.join(app_dir, "adb_manager.log")
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file)
        ]
    )
    logging.info("ADB Manager application started.")

def handle_exception(exc_type, exc_value, exc_traceback):
    """Handle uncaught exceptions and log them."""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logging.critical("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

sys.excepthook = handle_exception

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def main():
    multiprocessing.freeze_support()
    setup_logging()

    # Ensure only one instance of the application is running
    lock_file = QLockFile(os.path.join(QDir.tempPath(), "adb_manager.lock"))
    if not lock_file.tryLock(100):
        sys.exit(0)

    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(resource_path("ui/icon.png")))
    
    # Set Windows 11 native style
    if sys.platform == 'win32' and sys.getwindowsversion().build >= 22000:
        app.setStyle('windows11')
    
    try:
        # Create and show main window
        window = ADBManager()
        window.show()
        app.exec()
    except RuntimeError:
        # This will be raised if ADB is not found.
        # The error message is already shown in ADBCore.
        # The application will now exit gracefully.
        pass

if __name__ == '__main__':
    main()