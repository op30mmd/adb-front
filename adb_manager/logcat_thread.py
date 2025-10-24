import subprocess
import sys
from PyQt6.QtCore import QThread, pyqtSignal

def get_adb_path():
    """Get the path to the bundled adb executable"""
    if hasattr(sys, '_MEIPASS'):
        # Running in a PyInstaller bundle
        return os.path.join(sys._MEIPASS, 'adb_binary', 'adb.exe')
    # Running in a normal Python environment
    return os.path.join(os.path.abspath("."), "adb_binary", "adb.exe")

class LogcatThread(QThread):
    log_line = pyqtSignal(str)

    def __init__(self, device):
        super().__init__()
        self.device = device
        self.process = None

    def run(self):
        creation_flags = 0
        if sys.platform == "win32":
            creation_flags = subprocess.CREATE_NO_WINDOW

        cmd = [get_adb_path(), "-s", self.device, "logcat", "-v", "time"]
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace', creationflags=creation_flags)

        while True:
            line = self.process.stdout.readline()
            if not line:
                break
            self.log_line.emit(line.strip())

    def stop(self):
        if self.process:
            self.process.kill()
            self.process = None