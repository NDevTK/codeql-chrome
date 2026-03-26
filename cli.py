#!/usr/bin/env python3
"""CLI for CodeQL Chrome — headless JavaScript security analysis.

Usage:
    python cli.py https://example.com
    python cli.py --spider --depth 3 https://example.com
    python cli.py --spider --scope same-domain https://example.com https://other.com
    python cli.py --output results.sarif https://example.com
"""
import argparse
import json
import os
import sys
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.cdp_client import CDPClient, ContextInfo, ScriptInfo
from app.chrome_launcher import ChromeLauncher
from app.cleanup import cleanup_stale_temp_dirs
from app.codeql_daemon import CodeQLDaemon
from app.codeql_setup import download_and_install, is_installed
from app.config import find_chrome, find_codeql
from app.findings_store import FindingsStore
from app.spider import Spider, SpiderConfig
from app.workers import content_hash

# Same debounce as the GUI — wait N seconds after last script before analyzing
DEBOUNCE_SECS = 3.0


def log(msg: str):
    print(f"[*] {msg}", flush=True)


def warn(msg: str):
    print(f"[!] {msg}", file=sys.stderr, flush=True)


def err(msg: str):
    print(f"[ERROR] {msg}", file=sys.stderr, flush=True)


def parse_args():
    p = argparse.ArgumentParser(
        description="CodeQL Chrome — headless JavaScript security analyzer",
    )
    p.add_argument("urls", nargs="+", help="URLs to analyze")
    p.add_argument("--wait", type=float, default=5,
                   help="Seconds to wait per URL for scripts to load (default: 5)")
    p.add_argument("--port", type=int, default=9222, help="CDP port (default: 9222)")
    p.add_argument("--chrome", type=str, default=None, help="Path to Chrome executable")
    p.add_argument("--codeql", type=str, default=None, help="Path to CodeQL CLI executable")
    p.add_argument("--output", "-o", type=str, default=None,
                   help="Write merged SARIF output to this file")
    p.add_argument("--json", dest="json_output", action="store_true",
                   help="Print findings as JSON to stdout")
    p.add_argument("--no-cleanup", action="store_true",
                   help="Skip startup cleanup of stale temp dirs")
    p.add_argument("--clear", action="store_true",
                   help="Clear all persisted findings before running")
    p.add_argument("--spider", action="store_true",
                   help="Crawl links from each URL (BFS, same-origin by default)")
    p.add_argument("--depth", type=int, default=3,
                   help="Spider max crawl depth (default: 3)")
    p.add_argument("--max-pages", type=int, default=50,
                   help="Spider max pages to visit (default: 50)")
    p.add_argument("--scope", type=str, default="same-origin",
                   choices=["same-origin", "same-domain", "prefix", "regex"],
                   help="Spider scope (default: same-origin)")
    p.add_argument("--scope-pattern", type=str, default="",
                   help="Pattern for prefix/regex scope modes")
    return p.parse_args()


def ensure_codeql(codeql_path: str | None) -> str:
    path = codeql_path or find_codeql()
    if path:
        return path
    log("CodeQL not found — downloading bundle…")
    return download_and_install(on_progress=lambda msg: log(msg))



class CLIAnalysisPipeline:
    """Event-driven per-context analysis pipeline for the CLI.
    Uses the CodeQLDaemon for analysis. Scripts are snapshotted as they arrive
    so navigating away doesn't lose them.
    """

    def __init__(self, daemon: 'CodeQLDaemon', store: FindingsStore):
        self._daemon = daemon
        self._store = store
        self._analyzed_hashes: dict[str, str] = {}
        self._pending: dict[str, float] = {}
        self._scripts: dict[str, dict[str, ScriptInfo]] = {}
        self._ctx_labels: dict[str, str] = {}
        self._lock = threading.Lock()

    def on_script(self, info: ScriptInfo):
        ctx_key = info.context_key
        if not ctx_key:
            return
        with self._lock:
            if ctx_key not in self._scripts:
                self._scripts[ctx_key] = {}
            self._scripts[ctx_key][info.script_id] = info
            if info.page_url and info.page_url != "about:blank":
                self._ctx_labels[ctx_key] = info.page_url
            self._pending[ctx_key] = time.monotonic() + DEBOUNCE_SECS

    def process_pending(self):
        now = time.monotonic()
        ready = []
        with self._lock:
            for ctx_key, deadline in list(self._pending.items()):
                if now >= deadline:
                    ready.append(ctx_key)
                    del self._pending[ctx_key]
        for ctx_key in ready:
            self._submit_if_changed(ctx_key)

    def flush(self):
        with self._lock:
            ready = list(self._pending.keys())
            self._pending.clear()
        for ctx_key in ready:
            self._submit_if_changed(ctx_key)

    def wait_for_daemon(self):
        """Block until the daemon finishes all queued work."""
        self._daemon.wait_until_idle()

    def _submit_if_changed(self, ctx_key: str):
        with self._lock:
            scripts = dict(self._scripts.get(ctx_key, {}))
            label = self._ctx_labels.get(ctx_key, ctx_key)
        if not scripts:
            return
        h = content_hash(scripts)
        if self._analyzed_hashes.get(ctx_key) == h:
            return
        self._analyzed_hashes[ctx_key] = h
        log(f"Submitting context: {label}")
        self._daemon.submit(ctx_key, scripts, label)


def main():
    args = parse_args()

    if not args.no_cleanup:
        removed = cleanup_stale_temp_dirs()
        if removed:
            log(f"Startup cleanup: removed {removed} stale temp dir(s)")

    chrome_path = args.chrome or find_chrome()
    if not chrome_path:
        err("Chrome not found. Use --chrome to specify path.")
        return 1

    codeql_path = ensure_codeql(args.codeql)

    store = FindingsStore()
    if args.clear:
        store.clear()
        log("Cleared persisted findings")

    log(f"Chrome: {chrome_path}")
    log(f"CodeQL: {codeql_path}")
    if args.spider:
        log(f"Spider: depth={args.depth}, max_pages={args.max_pages}, scope={args.scope}")

    launcher = ChromeLauncher(
        chrome_path=chrome_path,
        cdp_port=args.port,
    )

    try:
        log("Launching Chrome…")
        launcher.launch()
        time.sleep(1)

        # Connect CDP client for script capture
        targets = launcher.get_page_targets()
        if not targets:
            err("No page targets found")
            return 1

        target = targets[0]
        page_ws = target.get("webSocketDebuggerUrl", "")
        tid = target.get("id", "")
        if not page_ws:
            err("No websocket URL for page target")
            return 1

        # Start the CodeQL daemon
        daemon = CodeQLDaemon(
            store=store,
            codeql_path=codeql_path,
            on_progress=lambda msg: log(msg),
        )
        daemon.start()
        log("CodeQL daemon started")

        # Single CDPClient for the entire session — scripts flow to the pipeline
        pipeline = CLIAnalysisPipeline(daemon, store)
        client = CDPClient(on_script=pipeline.on_script)
        client.connect(page_ws, page_url="about:blank", target_id=tid)
        page_client = client._page_clients[0]

        if args.spider:
            for i, url in enumerate(args.urls, 1):
                log(f"[{i}/{len(args.urls)}] Spidering from {url}")
                config = SpiderConfig(
                    scope=args.scope,
                    scope_pattern=args.scope_pattern,
                    max_depth=args.depth,
                    max_pages=args.max_pages,
                    wait_after_load=args.wait,
                )
                spider = Spider(
                    page_client=page_client,
                    config=config,
                    on_page_start=lambda u, d: log(f"  [{d}] {u}"),
                    on_page_done=lambda r: (
                        log(f"  {r.links_found} links found"),
                        pipeline.process_pending(),
                    ),
                )
                spider.crawl(url)
                pipeline.process_pending()
        else:
            for i, url in enumerate(args.urls, 1):
                log(f"[{i}/{len(args.urls)}] Navigating to {url}")
                page_client.navigate(url)
                log(f"  Waiting {args.wait}s for scripts…")

                deadline = time.monotonic() + args.wait
                last_count = 0
                while time.monotonic() < deadline:
                    time.sleep(0.5)
                    count = client.script_count
                    if count != last_count:
                        last_count = count
                        remaining = deadline - time.monotonic()
                        if remaining < 2:
                            deadline = time.monotonic() + 2
                    pipeline.process_pending()

                log(f"  {client.script_count} scripts captured")
                pipeline.process_pending()

        # Flush remaining contexts and wait for daemon to finish
        time.sleep(DEBOUNCE_SECS + 0.5)
        pipeline.flush()
        pipeline.wait_for_daemon()

        client.disconnect()
        daemon.stop()
        log("CodeQL daemon stopped")

    finally:
        log("Shutting down Chrome…")
        launcher.shutdown()

    # Output
    print(store.format_text())

    if args.json_output:
        print(json.dumps(store.to_json(), indent=2))

    if args.output:
        store.write_sarif(args.output)
        log(f"SARIF written to {args.output}")

    s = store.summary()
    return 1 if s["High"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
