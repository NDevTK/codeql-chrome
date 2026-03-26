import hashlib
import json
import os
import shutil
import urllib.request

from PySide6.QtCore import QThread, Signal

from app.cdp_client import CDPClient, ContextInfo, ScriptInfo
from app.chrome_launcher import ChromeLauncher
from app.codeql_setup import download_and_install as setup_codeql
from app.script_store import ScriptStore

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES_DIR = os.path.join(_PROJECT_ROOT, "sources")


def persist_sources(temp_source_root: str, ctx_hash: str) -> str:
    """Copy source files from temp dir to permanent sources/{ctx_hash}/.
    Returns the permanent source root path."""
    dest = os.path.join(SOURCES_DIR, ctx_hash)
    if os.path.isdir(dest):
        return dest
    os.makedirs(SOURCES_DIR, exist_ok=True)
    shutil.copytree(temp_source_root, dest)
    return dest


def content_hash(scripts: dict[str, ScriptInfo]) -> str:
    """Hash the actual source content of all scripts in a context.
    Same scripts with same content → same hash, regardless of URL or order."""
    h = hashlib.sha256()
    for source in sorted(s.source for s in scripts.values() if s.source):
        h.update(source.encode("utf-8", errors="replace"))
    return h.hexdigest()


class CodeQLSetupWorker(QThread):
    progress = Signal(str)
    finished_setup = Signal(str)
    error = Signal(str)

    def run(self):
        try:
            path = setup_codeql(on_progress=lambda msg: self.progress.emit(msg))
            self.finished_setup.emit(path)
        except Exception as e:
            self.error.emit(str(e))


class ChromeLaunchWorker(QThread):
    launched = Signal(str)
    targets_ready = Signal(list)
    error = Signal(str)
    progress = Signal(str)

    def __init__(self, launcher: ChromeLauncher, url: str = "about:blank"):
        super().__init__()
        self._launcher = launcher
        self._url = url

    def run(self):
        try:
            self.progress.emit("Launching Chrome…")
            ws_url = self._launcher.launch(self._url)
            self.progress.emit("Chrome launched, CDP ready")
            self.launched.emit(ws_url)
            targets = self._launcher.get_page_targets()
            self.targets_ready.emit(targets)
        except Exception as e:
            self.error.emit(str(e))


class CaptureWorker(QThread):
    script_captured = Signal(object)        # ScriptInfo
    context_created = Signal(object)        # ContextInfo
    context_destroyed = Signal(str)         # context_key
    chrome_died = Signal()
    error = Signal(str)

    def __init__(self, cdp_port: int):
        super().__init__()
        self._cdp_port = cdp_port
        self._client: CDPClient | None = None
        self._stop_flag = False
        self._attached_targets: set[str] = set()

    @property
    def client(self) -> CDPClient | None:
        return self._client

    def run(self):
        try:
            self._client = CDPClient(
                on_script=self._on_script,
                on_context_created=self._on_ctx_created,
                on_context_destroyed=self._on_ctx_destroyed,
            )
            self._poll_and_attach()
            while not self._stop_flag:
                self.msleep(1500)
                if not self._cdp_alive():
                    if not self._stop_flag:
                        self.chrome_died.emit()
                    break
                self._poll_and_attach()
        except Exception as e:
            self.error.emit(str(e))

    def _cdp_alive(self) -> bool:
        try:
            url = f"http://127.0.0.1:{self._cdp_port}/json/version"
            with urllib.request.urlopen(url, timeout=2) as resp:
                resp.read()
            return True
        except Exception:
            return False

    def _poll_and_attach(self):
        try:
            url = f"http://127.0.0.1:{self._cdp_port}/json"
            with urllib.request.urlopen(url, timeout=2) as resp:
                targets = json.loads(resp.read())
        except Exception:
            return

        for target in targets:
            if target.get("type") != "page":
                continue
            tid = target.get("id", "")
            if tid in self._attached_targets:
                continue
            ws_url = target.get("webSocketDebuggerUrl", "")
            page_url = target.get("url", "")
            if not ws_url:
                continue
            try:
                self._client.connect(ws_url, page_url=page_url, target_id=tid)
                self._attached_targets.add(tid)
            except Exception:
                pass

    def _on_script(self, info: ScriptInfo):
        self.script_captured.emit(info)

    def _on_ctx_created(self, info: ContextInfo):
        self.context_created.emit(info)

    def _on_ctx_destroyed(self, context_key: str):
        self.context_destroyed.emit(context_key)

    def stop_capture(self):
        self._stop_flag = True
        if self._client:
            self._client.disconnect()

    def get_scripts(self) -> dict[str, ScriptInfo]:
        if self._client:
            return self._client.scripts
        return {}

    def get_scripts_by_context(self) -> dict[str, dict[str, ScriptInfo]]:
        if self._client:
            return self._client.scripts_by_context()
        return {}

    def get_context_scripts(self, context_key: str) -> dict[str, ScriptInfo]:
        if self._client:
            return self._client.scripts_by_context().get(context_key, {})
        return {}

    def get_context_info(self, key: str) -> ContextInfo | None:
        if self._client:
            return self._client.get_context_info(key)
        return None

    def all_context_info(self) -> dict[str, ContextInfo]:
        if self._client:
            return self._client.all_context_info()
        return {}

    def remove_context(self, context_key: str):
        if self._client:
            self._client.remove_context(context_key)

    def get_page_client(self):
        """Return the first CDPPageClient (for the spider to drive)."""
        if self._client and self._client._page_clients:
            return self._client._page_clients[0]
        return None


class SpiderWorker(QThread):
    """Runs the spider in a background thread."""
    page_started = Signal(str, int)      # (url, depth)
    page_done = Signal(object)           # PageResult
    link_found = Signal(str)
    finished_crawl = Signal(int)         # total pages visited
    error = Signal(str)

    def __init__(self, page_client, config):
        super().__init__()
        from app.spider import Spider
        self._spider = Spider(
            page_client=page_client,
            config=config,
            on_page_start=lambda url, depth: self.page_started.emit(url, depth),
            on_page_done=lambda r: self.page_done.emit(r),
            on_link_found=lambda url: self.link_found.emit(url),
        )
        self._start_url = ""

    def set_start_url(self, url: str):
        self._start_url = url

    def run(self):
        try:
            self._spider.crawl(self._start_url)
            self.finished_crawl.emit(self._spider.visited_count)
        except Exception as e:
            self.error.emit(str(e))

    def stop(self):
        self._spider.stop()


