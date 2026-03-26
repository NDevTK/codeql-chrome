"""CodeQL daemon — parallel analysis with per-context database isolation.

Runs a thread pool of workers. Each worker creates its own CodeQL database
scoped to one execution context, so findings never cross-contaminate.
CPU threads and RAM are divided across workers to avoid over-subscription.
"""
import glob
import os
import subprocess
import shutil
import tempfile
import threading
from dataclasses import dataclass
from queue import Queue, Empty
from typing import Callable

from app.cdp_client import ScriptInfo
from app.config import CLIENT_SIDE_QUERIES, find_codeql
from app.findings_store import FindingsStore
from app.sarif_parser import Finding, SarifParser
from app.script_store import ScriptStore
from app.workers import content_hash, persist_sources


def _get_system_ram_mb() -> int:
    try:
        import ctypes
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("sullAvailExtendedVirtual", ctypes.c_ulonglong)]
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(stat)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
        return stat.ullTotalPhys // (1024 * 1024)
    except Exception:
        return 4096


@dataclass
class AnalysisRequest:
    context_key: str
    scripts: dict[str, ScriptInfo]
    label: str


class CodeQLDaemon:
    """Parallel CodeQL analysis daemon.

    - Thread pool processes multiple contexts simultaneously
    - Each context gets its own database (no cross-context FPs)
    - CPU and RAM divided across workers
    - Results go straight into the shared FindingsStore
    """

    def __init__(self, store: FindingsStore,
                 codeql_path: str | None = None,
                 max_workers: int = 0,
                 on_progress: Callable[[str], None] | None = None,
                 on_findings: Callable[[str, list[Finding]], None] | None = None):
        self._codeql = codeql_path or find_codeql()
        self._store = store
        self._on_progress = on_progress
        self._on_findings = on_findings

        total_cores = os.cpu_count() or 4
        total_ram = _get_system_ram_mb()

        # Default: use half the cores as workers (each gets 2+ threads)
        if max_workers <= 0:
            max_workers = max(1, total_cores // 4)
        self._max_workers = min(max_workers, total_cores)

        # Divide resources across workers
        self._threads_per_worker = max(1, total_cores // self._max_workers)
        self._ram_per_worker = max(2048, int(total_ram * 0.8) // self._max_workers)

        self._queue: Queue[AnalysisRequest | None] = Queue()
        self._workers: list[threading.Thread] = []
        self._running = False
        self._active_count = 0
        self._active_lock = threading.Lock()
        self._idle_event = threading.Event()
        self._idle_event.set()
        self._queries: list[str] = []

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_idle(self) -> bool:
        return self._idle_event.is_set()

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    def start(self):
        if self._running:
            return
        if not self._codeql:
            raise FileNotFoundError("CodeQL CLI not found")
        self._queries = self._resolve_queries()
        self._running = True

        self._emit_progress(
            f"CodeQL daemon: {self._max_workers} workers, "
            f"{self._threads_per_worker} threads each, "
            f"{self._ram_per_worker}MB RAM each"
        )

        for i in range(self._max_workers):
            t = threading.Thread(target=self._worker_loop, name=f"codeql-{i}", daemon=True)
            self._workers.append(t)
            t.start()

    def stop(self):
        self._running = False
        # Send one sentinel per worker to unblock them
        for _ in self._workers:
            self._queue.put(None)
        for t in self._workers:
            t.join(timeout=30)
        self._workers.clear()

    def submit(self, context_key: str, scripts: dict[str, ScriptInfo], label: str):
        self._queue.put(AnalysisRequest(
            context_key=context_key,
            scripts=scripts,
            label=label,
        ))

    def wait_until_idle(self, timeout: float = 600):
        self._idle_event.wait(timeout)

    # ── Worker pool ──

    def _worker_loop(self):
        while self._running:
            try:
                req = self._queue.get(timeout=1)
            except Empty:
                continue
            if req is None:
                break

            with self._active_lock:
                self._active_count += 1
                self._idle_event.clear()

            try:
                self._process_request(req)
            finally:
                with self._active_lock:
                    self._active_count -= 1
                    # Both checks under the lock — queue.qsize() is
                    # approximate but safe here since we only set idle
                    # when no workers are active AND nothing is queued.
                    if self._active_count == 0 and self._queue.qsize() == 0:
                        self._idle_event.set()

    def _process_request(self, req: AnalysisRequest):
        nonempty = {k: v for k, v in req.scripts.items()
                    if v.source and v.source.strip()}
        if not nonempty:
            return

        self._emit_progress(f"{req.label}: saving {len(nonempty)} scripts…")
        store = ScriptStore()
        store.save_all(nonempty)
        if store.file_count == 0:
            store.cleanup()
            return

        work_dir = tempfile.mkdtemp(prefix="codeql_work_")
        db_path = os.path.join(work_dir, "js-db")
        sarif_path = os.path.join(work_dir, "results.sarif")

        try:
            # Create database
            self._emit_progress(f"{req.label}: creating database ({store.file_count} files)…")
            rc = self._run_codeql([
                "database", "create", db_path,
                "--language=javascript",
                f"--source-root={store.base_dir}",
                "--overwrite",
                f"--threads={self._threads_per_worker}",
                f"--ram={self._ram_per_worker}",
            ])
            if rc != 0:
                self._emit_progress(f"{req.label}: database creation failed")
                return

            # Run analysis
            self._emit_progress(f"{req.label}: running analysis…")
            analyze_cmd = [
                "database", "analyze", db_path,
                f"--format=sarifv2.1.0",
                f"--output={sarif_path}",
                f"--threads={self._threads_per_worker}",
                f"--ram={self._ram_per_worker}",
            ] + self._queries
            rc = self._run_codeql(analyze_cmd)

            if not os.path.isfile(sarif_path):
                self._emit_progress(f"{req.label}: no SARIF output")
                return

            # Parse results
            parser = SarifParser(source_root=store.base_dir)
            findings = parser.parse(sarif_path)

            # Persist source files if there are findings
            if findings:
                ctx_h = content_hash(nonempty)
                perm_root = persist_sources(store.base_dir, ctx_h)
            else:
                perm_root = store.base_dir

            for f in findings:
                f.source_root = perm_root
                f.page_context = req.label
                f.context_key = req.context_key
                si = store.reverse_lookup(f.file_path)
                if si:
                    f.script_url = si.display_name

            self._store.add(findings)
            self._emit_progress(f"{req.label}: {len(findings)} findings")

            if findings and self._on_findings:
                self._on_findings(req.context_key, findings)

        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    def _run_codeql(self, args: list[str]) -> int:
        creation_flags = 0
        if os.name == "nt":
            creation_flags = subprocess.CREATE_NO_WINDOW
        cmd = [self._codeql] + args
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=creation_flags,
        )
        for line in proc.stdout:
            if self._on_progress:
                self._on_progress(line.rstrip())
        proc.wait()
        return proc.returncode

    def _resolve_queries(self) -> list[str]:
        codeql_dir = os.path.dirname(self._codeql)
        pack_pattern = os.path.join(
            codeql_dir, "qlpacks", "codeql", "javascript-queries", "*"
        )
        pack_dirs = sorted(glob.glob(pack_pattern), reverse=True)
        if not pack_dirs:
            return ["javascript-security-extended.qls"]
        pack_dir = pack_dirs[0]
        resolved = []
        for q in CLIENT_SIDE_QUERIES:
            full = os.path.join(pack_dir, q)
            if os.path.isfile(full):
                resolved.append(full)
        return resolved or ["javascript-security-extended.qls"]

    def _emit_progress(self, msg: str):
        if self._on_progress:
            self._on_progress(msg)
