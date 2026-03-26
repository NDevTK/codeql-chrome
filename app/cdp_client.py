import json
import threading
from dataclasses import dataclass, field
from typing import Callable

import websocket


@dataclass
class ScriptInfo:
    script_id: str
    url: str
    source: str = ""
    start_line: int = 0
    start_column: int = 0
    end_line: int = 0
    end_column: int = 0
    hash_: str = ""
    execution_context_id: int = 0
    source_map_url: str = ""
    is_module: bool = False
    length: int = 0
    page_url: str = ""
    page_urls: list[str] = field(default_factory=list)
    origin: str = ""
    frame_id: str = ""
    context_key: str = ""  # unique per document lifecycle

    @property
    def display_name(self) -> str:
        if self.url:
            return self.url.split("?")[0].split("#")[0]
        return f"[VM script {self.script_id}]"

    @property
    def is_inline(self) -> bool:
        if not self.url:
            return False
        return not self.url.endswith(".js") and not self.url.startswith("debugger://")

    @property
    def is_dynamic(self) -> bool:
        return not self.url or self.url.startswith("debugger://")

    @property
    def pages_str(self) -> str:
        if self.page_urls:
            return ", ".join(dict.fromkeys(self.page_urls))
        return self.page_url or ""


@dataclass
class ContextInfo:
    """Metadata for a single execution context (one per document/frame lifecycle)."""
    context_id: int
    unique_id: str          # Runtime.executionContextCreated → context.uniqueId
    origin: str
    frame_id: str
    is_default: bool
    page_url: str           # the tab's URL when this context was created
    name: str = ""          # human label from CDP (e.g. extension name)
    alive: bool = True

    @property
    def context_key(self) -> str:
        """Globally unique key for this document context."""
        return self.unique_id or f"{self.frame_id}:{self.context_id}"

    @property
    def label(self) -> str:
        page = self.page_url or ""
        origin = self.origin or ""
        # Ignore about:blank / empty as a meaningful page_url
        if page in ("", "about:blank"):
            return origin or f"context-{self.context_id}"
        # Truncate data: URLs for readability
        display_page = (page[:60] + "…") if page.startswith("data:") and len(page) > 60 else page
        # origin is scheme+host (no path), page_url has the full path.
        # If page_url starts with origin, this is the main frame.
        if origin and not page.startswith(origin):
            return f"{origin} (iframe in {display_page})"
        return display_page


class CDPPageClient:
    """Connects to a single page target via CDP.  Tracks execution contexts
    (main frame, iframes, workers) and tags every captured script with its
    context_key so the analyser can partition per-document."""

    def __init__(self, page_url: str, target_id: str = "",
                 on_script: Callable[[ScriptInfo], None] | None = None,
                 on_context_created: Callable[[ContextInfo], None] | None = None,
                 on_context_destroyed: Callable[[str], None] | None = None):
        self._page_url = page_url
        self._target_id = target_id
        self._on_script = on_script
        self._on_context_created = on_context_created
        self._on_context_destroyed = on_context_destroyed

        self._msg_id = 0
        self._lock = threading.Lock()
        self._scripts: dict[str, ScriptInfo] = {}
        self._pending_sources: dict[int, str] = {}
        self._contexts: dict[int, ContextInfo] = {}  # contextId → ContextInfo
        self._ws: websocket.WebSocketApp | None = None
        self._thread: threading.Thread | None = None
        self._connected = threading.Event()
        # Sync response waiting for navigate()/evaluate()
        self._waiters: dict[int, threading.Event] = {}
        self._waiter_results: dict[int, dict] = {}

    @property
    def scripts(self) -> dict[str, ScriptInfo]:
        return dict(self._scripts)

    @property
    def contexts(self) -> dict[int, ContextInfo]:
        return dict(self._contexts)

    def connect(self, ws_url: str):
        self._connected.clear()
        self._ws = websocket.WebSocketApp(
            ws_url,
            on_open=self._on_open,
            on_message=self._on_message,
            on_error=self._on_error,
            on_close=self._on_close,
        )
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if not self._connected.wait(timeout=10):
            raise TimeoutError("Failed to connect to CDP page target")

    def _run(self):
        self._ws.run_forever(
            ping_interval=10, ping_timeout=5,
            suppress_origin=True,
        )

    def _next_id(self) -> int:
        with self._lock:
            self._msg_id += 1
            return self._msg_id

    def _send(self, method: str, params: dict | None = None) -> int:
        msg_id = self._next_id()
        msg = {"id": msg_id, "method": method}
        if params:
            msg["params"] = params
        try:
            self._ws.send(json.dumps(msg))
        except Exception:
            pass
        return msg_id

    def _on_open(self, ws):
        self._connected.set()
        self._send("Runtime.enable")
        self._send("Debugger.enable")
        self._send("Page.enable")
        # Auto-attach to iframes so we capture their scripts too
        self._send("Target.setAutoAttach", {
            "autoAttach": True,
            "waitForDebuggerOnStart": False,
            "flatten": True,  # use flat session IDs, not nested
        })

    def _on_message(self, ws, message: str):
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            return
        if "method" in data:
            self._handle_event(data)
        elif "id" in data and "result" in data:
            self._handle_response(data)

    def _send_to_session(self, session_id: str, method: str, params: dict | None = None):
        """Send a CDP command to a child session (iframe target)."""
        msg_id = self._next_id()
        msg = {"id": msg_id, "method": method, "sessionId": session_id}
        if params:
            msg["params"] = params
        try:
            self._ws.send(json.dumps(msg))
        except Exception:
            pass

    def _handle_event(self, data: dict):
        method = data.get("method", "")
        params = data.get("params", {})

        if method == "Target.attachedToTarget":
            self._on_target_attached(params)
        elif method == "Runtime.executionContextCreated":
            self._on_ctx_created(params)
        elif method == "Runtime.executionContextDestroyed":
            self._on_ctx_destroyed(params)
        elif method == "Runtime.executionContextsCleared":
            self._on_ctx_cleared()
        elif method == "Debugger.scriptParsed":
            self._on_script_parsed(params)
        elif method == "Page.frameNavigated":
            self._on_frame_navigated(params)

    def _on_target_attached(self, params: dict):
        """A child target (iframe, worker) was auto-attached.
        Enable debugger and runtime on its session to capture scripts."""
        session_id = params.get("sessionId", "")
        target_info = params.get("targetInfo", {})
        if not session_id:
            return
        self._send_to_session(session_id, "Runtime.enable")
        self._send_to_session(session_id, "Debugger.enable")
        self._send_to_session(session_id, "Page.enable")

    def _on_ctx_created(self, params: dict):
        ctx = params.get("context", {})
        ctx_id = ctx.get("id", 0)
        aux = ctx.get("auxData", {})
        info = ContextInfo(
            context_id=ctx_id,
            unique_id=ctx.get("uniqueId", ""),
            origin=ctx.get("origin", ""),
            frame_id=aux.get("frameId", ""),
            is_default=aux.get("isDefault", False),
            page_url=self._page_url,
            name=ctx.get("name", ""),
        )
        with self._lock:
            self._contexts[ctx_id] = info
        if self._on_context_created:
            self._on_context_created(info)

    def _on_ctx_destroyed(self, params: dict):
        ctx_id = params.get("executionContextId", 0)
        with self._lock:
            info = self._contexts.get(ctx_id)
            if info:
                info.alive = False
                key = info.context_key
            else:
                key = ""
        if key and self._on_context_destroyed:
            self._on_context_destroyed(key)

    def _on_ctx_cleared(self):
        """All contexts for this target destroyed (full page navigation)."""
        with self._lock:
            keys = []
            for info in self._contexts.values():
                if info.alive:
                    info.alive = False
                    keys.append(info.context_key)
            self._contexts.clear()
        for key in keys:
            if self._on_context_destroyed:
                self._on_context_destroyed(key)

    def _on_frame_navigated(self, params: dict):
        """Page.frameNavigated — update page_url for this target and
        any existing contexts that belong to this frame."""
        frame = params.get("frame", {})
        frame_url = frame.get("url", "")
        frame_id = frame.get("id", "")
        # Only update for top-level frame (no parentId = main frame)
        if not frame.get("parentId") and frame_url:
            self._page_url = frame_url
            with self._lock:
                for info in self._contexts.values():
                    if info.frame_id == frame_id:
                        info.page_url = frame_url

    def _on_script_parsed(self, params: dict):
        script_id = params.get("scriptId", "")
        ctx_id = params.get("executionContextId", 0)

        with self._lock:
            ctx_info = self._contexts.get(ctx_id)

        origin = ctx_info.origin if ctx_info else ""
        frame_id = ctx_info.frame_id if ctx_info else ""
        context_key = ctx_info.context_key if ctx_info else f"_unknown:{ctx_id}"

        info = ScriptInfo(
            script_id=script_id,
            url=params.get("url", ""),
            start_line=params.get("startLine", 0),
            start_column=params.get("startColumn", 0),
            end_line=params.get("endLine", 0),
            end_column=params.get("endColumn", 0),
            hash_=params.get("hash", ""),
            execution_context_id=ctx_id,
            source_map_url=params.get("sourceMapURL", ""),
            is_module=params.get("isModule", False),
            length=params.get("length", 0),
            page_url=self._page_url,
            page_urls=[self._page_url] if self._page_url else [],
            origin=origin,
            frame_id=frame_id,
            context_key=context_key,
        )
        self._scripts[script_id] = info
        msg_id = self._send("Debugger.getScriptSource", {"scriptId": script_id})
        with self._lock:
            self._pending_sources[msg_id] = script_id

    def _handle_response(self, data: dict):
        msg_id = data["id"]
        result = data.get("result", {})

        # Check if a sync waiter is waiting for this response
        with self._lock:
            waiter = self._waiters.pop(msg_id, None)
        if waiter:
            self._waiter_results[msg_id] = result
            waiter.set()
            return

        with self._lock:
            script_id = self._pending_sources.pop(msg_id, None)
        if script_id and script_id in self._scripts:
            self._scripts[script_id].source = result.get("scriptSource", "")
            if self._on_script:
                self._on_script(self._scripts[script_id])

    def send_and_wait(self, method: str, params: dict | None = None,
                      timeout: float = 15) -> dict:
        """Send a CDP command and block until the response arrives."""
        msg_id = self._send(method, params)
        event = threading.Event()
        with self._lock:
            self._waiters[msg_id] = event
        if not event.wait(timeout):
            with self._lock:
                self._waiters.pop(msg_id, None)
            raise TimeoutError(f"CDP {method} timed out after {timeout}s")
        return self._waiter_results.pop(msg_id, {})

    def navigate(self, url: str, timeout: float = 15):
        """Navigate this page target to a URL and wait for the response."""
        from urllib.parse import urlparse
        scheme = urlparse(url).scheme
        if scheme not in ("http", "https", "about", "data", ""):
            raise ValueError(f"Refused to navigate to {scheme}: URL")
        self.send_and_wait("Page.navigate", {"url": url}, timeout=timeout)

    def evaluate(self, expression: str, timeout: float = 10) -> dict:
        """Run JS in the page and return the result synchronously."""
        return self.send_and_wait("Runtime.evaluate", {
            "expression": expression,
            "returnByValue": True,
        }, timeout=timeout)

    def _on_error(self, ws, error):
        pass

    def _on_close(self, ws, close_status_code, close_msg):
        self._connected.clear()

    def disconnect(self):
        if self._ws:
            try:
                self._ws.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=3)
        self._ws = None
        self._thread = None

    def is_connected(self) -> bool:
        return self._connected.is_set()


class CDPClient:
    """Manages multiple CDPPageClient instances.  Provides scripts grouped
    by context_key so the analyser creates one CodeQL DB per document."""

    def __init__(self,
                 on_script: Callable[[ScriptInfo], None] | None = None,
                 on_context_created: Callable[[ContextInfo], None] | None = None,
                 on_context_destroyed: Callable[[str], None] | None = None):
        self._on_script = on_script
        self._on_context_created = on_context_created
        self._on_context_destroyed = on_context_destroyed
        self._lock = threading.Lock()
        self._page_clients: list[CDPPageClient] = []
        # context_key → {script_id → ScriptInfo}
        self._context_scripts: dict[str, dict[str, ScriptInfo]] = {}
        # context_key → ContextInfo (latest for that key)
        self._context_info: dict[str, ContextInfo] = {}
        # dedup: (url, hash) → canonical script_id within each context
        self._seen: dict[str, set[str]] = {}  # context_key → set of "url|hash"

    @property
    def scripts(self) -> dict[str, ScriptInfo]:
        """Flat dict of all scripts (for backward compat / capture count)."""
        with self._lock:
            merged = {}
            for ctx_scripts in self._context_scripts.values():
                merged.update(ctx_scripts)
            return merged

    @property
    def script_count(self) -> int:
        with self._lock:
            return sum(len(s) for s in self._context_scripts.values())

    def scripts_by_context(self) -> dict[str, dict[str, ScriptInfo]]:
        """Returns {context_key: {script_id: ScriptInfo}} — the core
        structure for per-context CodeQL analysis."""
        with self._lock:
            return {k: dict(v) for k, v in self._context_scripts.items()}

    def get_context_info(self, context_key: str) -> ContextInfo | None:
        with self._lock:
            return self._context_info.get(context_key)

    def all_context_info(self) -> dict[str, ContextInfo]:
        with self._lock:
            return dict(self._context_info)

    def connect(self, ws_url: str, page_url: str = "", target_id: str = ""):
        client = CDPPageClient(
            page_url=page_url,
            target_id=target_id,
            on_script=self._on_page_script,
            on_context_created=self._on_ctx_created,
            on_context_destroyed=self._on_ctx_destroyed,
        )
        client.connect(ws_url)
        self._page_clients.append(client)

    def _on_ctx_created(self, info: ContextInfo):
        with self._lock:
            self._context_info[info.context_key] = info
            if info.context_key not in self._context_scripts:
                self._context_scripts[info.context_key] = {}
                self._seen[info.context_key] = set()
        if self._on_context_created:
            self._on_context_created(info)

    def _on_ctx_destroyed(self, context_key: str):
        if self._on_context_destroyed:
            self._on_context_destroyed(context_key)

    def _on_page_script(self, info: ScriptInfo):
        ctx_key = info.context_key
        with self._lock:
            if ctx_key not in self._context_scripts:
                self._context_scripts[ctx_key] = {}
                self._seen[ctx_key] = set()

            # Dedup within context by (url, hash)
            dedup_key = f"{info.url}|{info.hash_}" if info.hash_ else ""
            if dedup_key and dedup_key in self._seen[ctx_key]:
                return
            if dedup_key:
                self._seen[ctx_key].add(dedup_key)

            self._context_scripts[ctx_key][info.script_id] = info

        if self._on_script:
            self._on_script(info)

    def remove_context(self, context_key: str):
        """Remove all data for a destroyed context."""
        with self._lock:
            self._context_scripts.pop(context_key, None)
            self._context_info.pop(context_key, None)
            self._seen.pop(context_key, None)

    def disconnect(self):
        for client in self._page_clients:
            client.disconnect()
        self._page_clients.clear()

    def is_connected(self) -> bool:
        return any(c.is_connected() for c in self._page_clients)
