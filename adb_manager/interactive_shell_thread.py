import subprocess
import threading
import queue
import time
import sys
import os

if sys.platform != "win32":
    import select
    import fcntl
    import errno

class InteractiveShellThread(threading.Thread):
    def __init__(self, device_serial):
        super().__init__(daemon=True)
        self.device_serial = device_serial
        self.process = None
        self.output_queue = queue.Queue()
        self.input_queue = queue.Queue()
        self.running = False
        self.stop_event = threading.Event()
        
    def run(self):
        """Main thread execution"""
        self.running = True
        
        # Construct the ADB command
        if sys.platform == "win32":
            # Windows-specific handling
            cmd = ["adb", "-s", self.device_serial, "shell"]
            # Set up environment for Windows
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            
            # Use CREATE_NEW_PROCESS_GROUP on Windows
            creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,  # Unbuffered
                universal_newlines=False,  # Binary mode
                env=env,
                creationflags=creation_flags
            )
        else:
            # Unix-like systems
            cmd = ["adb", "-s", self.device_serial, "shell", "-tt"]
            
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                universal_newlines=False,
                preexec_fn=os.setsid  # Create new session
            )
            
            # Make stdout non-blocking on Unix
            self._make_non_blocking(self.process.stdout)
            self._make_non_blocking(self.process.stderr)
        
        # Start reader threads
        stdout_reader = threading.Thread(target=self._read_output, args=(self.process.stdout, "stdout"))
        stderr_reader = threading.Thread(target=self._read_output, args=(self.process.stderr, "stderr"))
        input_writer = threading.Thread(target=self._write_input)
        
        stdout_reader.daemon = True
        stderr_reader.daemon = True
        input_writer.daemon = True
        
        stdout_reader.start()
        stderr_reader.start()
        input_writer.start()
        
        # Wait for process to complete or stop event
        while self.running and not self.stop_event.is_set():
            if self.process.poll() is not None:
                break
            time.sleep(0.1)
        
        self.cleanup()
    
    def _make_non_blocking(self, stream):
        """Make a stream non-blocking on Unix-like systems"""
        if sys.platform != "win32":
            fd = stream.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    
    def _read_output(self, stream, stream_name):
        """Read output from stream continuously"""
        while self.running and not self.stop_event.is_set():
            try:
                if sys.platform == "win32":
                    # Windows: Use small reads with timeout
                    data = stream.read(1)
                    if data:
                        self.output_queue.put(data)
                    else:
                        time.sleep(0.01)
                else:
                    # Unix: Non-blocking read
                    try:
                        data = stream.read(4096)
                        if data:
                            self.output_queue.put(data)
                        else:
                            break  # EOF
                    except IOError as e:
                        if e.errno != errno.EAGAIN:
                            break
                        time.sleep(0.01)
            except Exception as e:
                print(f"Error reading {stream_name}: {e}")
                break
    
    def _write_input(self):
        """Write input to the process"""
        while self.running and not self.stop_event.is_set():
            try:
                command = self.input_queue.get(timeout=0.1)
                if command is not None and self.process and self.process.stdin:
                    # Ensure command ends with newline
                    if not command.endswith('\n'):
                        command += '\n'
                    
                    self.process.stdin.write(command.encode('utf-8'))
                    self.process.stdin.flush()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error writing input: {e}")
    
    def send_command(self, command):
        """Send a command to the shell"""
        if self.running:
            self.input_queue.put(command)

    def send_ctrl_c(self):
        if self.process and self.process.stdin:
            self.process.stdin.write(b'\x03')
            self.process.stdin.flush()
    
    def get_output(self, timeout=0.1):
        """Get output from the shell"""
        output = b""
        deadline = time.time() + timeout
        
        while time.time() < deadline:
            try:
                chunk = self.output_queue.get_nowait()
                output += chunk
            except queue.Empty:
                if output:  # If we have some output, return it
                    break
                time.sleep(0.01)
        
        return output.decode('utf-8', errors='replace')
    
    def cleanup(self):
        """Clean up resources"""
        self.running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except:
                if sys.platform == "win32":
                    subprocess.run(["taskkill", "/F", "/PID", str(self.process.pid)], 
                                 capture_output=True)
                else:
                    self.process.kill()
            
            self.process = None
    
    def stop(self):
        """Stop the thread"""
        self.stop_event.set()
        self.running = False
