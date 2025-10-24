#!/usr/bin/env python

import sys
import multiprocessing
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import QLockFile, QDir

from ui.main_window import ADBManager

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