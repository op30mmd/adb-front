import subprocess
from PyQt6.QtCore import QThread, pyqtSignal

class ADBThread(QThread):
    """Thread for running ADB commands without blocking UI"""
    output = pyqtSignal(str)
    error = pyqtSignal(str)
    finished = pyqtSignal()
    
    def __init__(self, command):
        super().__init__()
        self.command = command
        
    def run(self):
        try:
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(self.command, capture_output=True, 
                                  timeout=30, check=True, text=True, encoding='utf-8', errors='replace', creationflags=creation_flags)
            if result.stdout:
                self.output.emit(result.stdout)
            if result.stderr:
                self.error.emit(result.stderr)
        except FileNotFoundError:
            self.error.emit(f"Command not found: {self.command[0]}")
        except subprocess.TimeoutExpired:
            self.error.emit("Command timed out")
        except subprocess.CalledProcessError as e:
            self.error.emit(e.stderr)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.finished.emit()