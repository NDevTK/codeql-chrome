import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

from app.config import CDP_PORT, find_chrome


def _port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


class ChromeLauncher:
    def __init__(self, chrome_path: str | None = None, cdp_port: int = CDP_PORT):
        self._chrome_path = chrome_path or find_chrome()
        if not (1024 <= cdp_port <= 65535):
            raise ValueError(f"CDP port must be 1024-65535, got {cdp_port}")
        self._cdp_port = cdp_port
        self._process: subprocess.Popen | None = None
        self._temp_profile_dir: str | None = None
        self._owns_process = False  # True if we launched Chrome

    @property
    def cdp_port(self) -> int:
        return self._cdp_port

    @property
    def profile_dir(self) -> str | None:
        return self._temp_profile_dir

    @property
    def is_running(self) -> bool:
        if self._process is not None:
            return self._process.poll() is None
        return _port_in_use(self._cdp_port)

    def launch(self, url: str = "about:blank", timeout: float = 10.0) -> str:
        """Launch Chrome or connect to an existing instance on the CDP port."""
        if _port_in_use(self._cdp_port):
            # Reuse existing Chrome
            self._owns_process = False
            return self._wait_for_cdp(timeout)

        if not self._chrome_path:
            raise FileNotFoundError("Chrome executable not found")

        # Persistent profile so cookies/logins survive across sessions
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._temp_profile_dir = os.path.join(project_root, "chrome-profile")
        os.makedirs(self._temp_profile_dir, exist_ok=True)

        cmd = [
            self._chrome_path,
            f"--remote-debugging-port={self._cdp_port}",
            f"--user-data-dir={self._temp_profile_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            url,
        ]

        creation_flags = 0
        if os.name == "nt":
            creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP

        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags,
        )
        self._owns_process = True

        ws_url = self._wait_for_cdp(timeout)
        return ws_url

    def _wait_for_cdp(self, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data = self._cdp_get("/json/version")
                return data.get("webSocketDebuggerUrl", "")
            except Exception:
                time.sleep(0.3)
        raise TimeoutError(f"Chrome CDP did not become ready within {timeout}s")

    def _cdp_get(self, path: str):
        url = f"http://127.0.0.1:{self._cdp_port}{path}"
        with urllib.request.urlopen(url, timeout=2) as resp:
            return json.loads(resp.read())

    def get_page_targets(self) -> list[dict]:
        try:
            targets = self._cdp_get("/json")
            return [t for t in targets if t.get("type") == "page"]
        except Exception:
            return []

    def shutdown(self):
        if self._process and self._owns_process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None
        # Profile is persistent — don't delete it
