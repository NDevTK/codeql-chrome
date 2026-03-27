import os
import subprocess
import tempfile

from app.config import CODEQL_QUERY_SUITE, find_codeql


def _get_system_ram_mb() -> int:
    """Best-effort system RAM detection. Returns MB."""
    try:
        import shutil
        total, _, _ = shutil.disk_usage("/")  # fallback
        # Try psutil if available
        import psutil
        return psutil.virtual_memory().total // (1024 * 1024)
    except ImportError:
        pass
    # Windows fallback
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
        pass
    return 4096  # conservative default


class CodeQLRunner:
    def __init__(self, source_dir: str, codeql_path: str | None = None,
                 threads: int = 0, ram_mb: int = 0):
        self._codeql = codeql_path or find_codeql()
        self._source_dir = source_dir
        work = tempfile.mkdtemp(prefix="codeql_work_")
        self._db_path = os.path.join(work, "js-db")
        self._sarif_path = os.path.join(work, "results.sarif")
        # threads=0 means "use all cores"
        self._threads = threads
        # ram=0 means "auto-detect, use 80% of system RAM"
        if ram_mb > 0:
            self._ram = ram_mb
        else:
            self._ram = max(2048, int(_get_system_ram_mb() * 0.8))

    @property
    def codeql_path(self) -> str | None:
        return self._codeql

    @property
    def db_path(self) -> str:
        return self._db_path

    @property
    def sarif_path(self) -> str:
        return self._sarif_path

    def create_database(self, on_output: callable = None) -> subprocess.CompletedProcess:
        if not self._codeql:
            raise FileNotFoundError(
                "CodeQL CLI not found. Download from:\n"
                "https://github.com/github/codeql-cli-binaries/releases\n"
                "Extract and add to PATH or configure in Settings."
            )

        cmd = [
            self._codeql,
            "database", "create",
            self._db_path,
            "--language=javascript",
            f"--source-root={self._source_dir}",
            "--overwrite",
            f"--threads={self._threads}",
            f"--ram={self._ram}",
        ]

        return self._run(cmd, on_output)

    def _resolve_queries(self) -> list[str]:
        return [CODEQL_QUERY_SUITE]

    def run_analysis(self, query_suite: str | None = None,
                     on_output: callable = None) -> subprocess.CompletedProcess:
        if not self._codeql:
            raise FileNotFoundError("CodeQL CLI not found")

        cmd = [
            self._codeql,
            "database", "analyze",
            self._db_path,
            f"--format=sarifv2.1.0",
            f"--output={self._sarif_path}",
            f"--threads={self._threads}",
            f"--ram={self._ram}",
        ]

        if query_suite:
            cmd.append(query_suite)
        else:
            queries = self._resolve_queries()
            if queries:
                cmd.extend(queries)
            else:
                # Fallback to full suite if resolution fails
                cmd.append("javascript-security-extended.qls")

        return self._run(cmd, on_output)

    def _run(self, cmd: list[str], on_output: callable = None) -> subprocess.CompletedProcess:
        creation_flags = 0
        if os.name == "nt":
            creation_flags = subprocess.CREATE_NO_WINDOW

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=creation_flags,
        )

        output_lines = []
        for line in proc.stdout:
            output_lines.append(line)
            if on_output:
                on_output(line.rstrip())

        proc.wait()

        return subprocess.CompletedProcess(
            args=cmd,
            returncode=proc.returncode,
            stdout="".join(output_lines),
        )

    def cleanup(self):
        import shutil
        parent = os.path.dirname(self._db_path)
        if os.path.isdir(parent):
            shutil.rmtree(parent, ignore_errors=True)
