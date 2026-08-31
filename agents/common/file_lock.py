import os
import time

class FileLock:
    def __init__(self, lock_file: str, timeout_seconds: float = 10.0):
        self.lock_file = lock_file
        self.timeout = timeout_seconds
        self.fd = None

    def __enter__(self):
        start = time.time()
        os.makedirs(os.path.dirname(os.path.abspath(self.lock_file)), exist_ok=True)
        while True:
            try:
                self.fd = os.open(self.lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                return self
            except FileExistsError:
                if time.time() - start > self.timeout:
                    try:
                        os.remove(self.lock_file)
                    except OSError:
                        pass
                else:
                    time.sleep(0.05)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.fd is not None:
            os.close(self.fd)
            try:
                os.remove(self.lock_file)
            except OSError:
                pass
