import os

from PySide6.QtCore import Qt, QFileSystemWatcher, QSettings, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStatusBar,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from app.cdp_client import ContextInfo, ScriptInfo
from app.chrome_launcher import ChromeLauncher
from app.codeql_setup import is_installed as codeql_is_installed
from app.config import find_chrome, find_codeql, verify_prerequisites
from app.findings_store import FindingsStore
from app.sarif_parser import Finding, TraceStep
from app.codeql_daemon import CodeQLDaemon
from app.spider import SpiderConfig
from app.workers import (
    CaptureWorker,
    ChromeLaunchWorker,
    CodeQLSetupWorker,
    SpiderWorker,
    content_hash,
)
from gui.findings_panel import FindingsPanel
from gui.source_panel import SourcePanel
from gui.toolbar import AnalysisToolbar
from gui.trace_panel import TracePanel

# Seconds to wait after the last script arrives before auto-analyzing a context
ANALYSIS_DEBOUNCE_SECS = 3


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(500)

        settings = QSettings("CodeQLChrome", "CodeQLChrome")
        layout = QFormLayout(self)

        self._chrome_edit = QLineEdit(
            settings.value("chrome_path", find_chrome() or "")
        )
        chrome_row = QHBoxLayout()
        chrome_row.addWidget(self._chrome_edit)
        chrome_browse = QPushButton("Browse…")
        chrome_browse.clicked.connect(
            lambda: self._browse(self._chrome_edit, "Chrome (*.exe)")
        )
        chrome_row.addWidget(chrome_browse)
        layout.addRow("Chrome:", chrome_row)

        self._codeql_edit = QLineEdit(
            settings.value("codeql_path", find_codeql() or "")
        )
        codeql_row = QHBoxLayout()
        codeql_row.addWidget(self._codeql_edit)
        codeql_browse = QPushButton("Browse…")
        codeql_browse.clicked.connect(
            lambda: self._browse(self._codeql_edit, "CodeQL (*.exe)")
        )
        codeql_row.addWidget(codeql_browse)
        layout.addRow("CodeQL CLI:", codeql_row)

        self._port_edit = QLineEdit(settings.value("cdp_port", "9222"))
        layout.addRow("CDP Port:", self._port_edit)

        btn_row = QHBoxLayout()
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self._save)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(save_btn)
        btn_row.addWidget(cancel_btn)
        layout.addRow(btn_row)

    def _browse(self, edit: QLineEdit, filter_: str):
        path, _ = QFileDialog.getOpenFileName(self, "Select Executable", "", filter_)
        if path:
            edit.setText(path)

    def _save(self):
        settings = QSettings("CodeQLChrome", "CodeQLChrome")
        settings.setValue("chrome_path", self._chrome_edit.text())
        settings.setValue("codeql_path", self._codeql_edit.text())
        settings.setValue("cdp_port", self._port_edit.text())
        self.accept()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CodeQL Chrome — JavaScript Security Analyzer")
        self.resize(1400, 850)

        self._launcher: ChromeLauncher | None = None
        self._launch_worker: ChromeLaunchWorker | None = None
        self._capture_worker: CaptureWorker | None = None
        self._setup_worker: CodeQLSetupWorker | None = None
        self._spider_worker: SpiderWorker | None = None
        self._store = FindingsStore()
        self._daemon: CodeQLDaemon | None = None
        self._browser_ws_url: str = ""
        self._script_count = 0
        self._codeql_ready = False
        self._setup_then_launch = False

        # Per-context debounce timers and content hashes
        self._debounce_timers: dict[str, QTimer] = {}
        self._analyzed_hashes: dict[str, str] = {}

        self._setup_ui()
        self._setup_tray()
        self._check_prerequisites()
        self._load_persisted_findings()

        QTimer.singleShot(100, self._auto_start)

    # ── UI Setup ──

    def _setup_ui(self):
        self._toolbar = AnalysisToolbar(self)
        self.addToolBar(self._toolbar)

        self._toolbar.launch_requested.connect(self._on_launch)
        self._toolbar.capture_requested.connect(self._on_capture)
        self._toolbar.stop_capture_requested.connect(self._on_stop_capture)
        self._toolbar.spider_requested.connect(self._on_spider)
        self._toolbar.stop_spider_requested.connect(self._on_stop_spider)
        self._toolbar.clear_findings_requested.connect(self._on_clear_findings)
        self._toolbar.settings_requested.connect(self._on_settings)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(4, 4, 4, 4)

        outer_splitter = QSplitter(Qt.Horizontal)

        self._findings_panel = FindingsPanel()
        self._findings_panel.finding_selected.connect(self._on_finding_selected)
        outer_splitter.addWidget(self._findings_panel)

        right_splitter = QSplitter(Qt.Vertical)

        self._trace_panel = TracePanel()
        self._trace_panel.step_selected.connect(self._on_trace_step_selected)
        right_splitter.addWidget(self._trace_panel)

        self._source_panel = SourcePanel()
        right_splitter.addWidget(self._source_panel)

        right_splitter.setSizes([250, 400])
        outer_splitter.addWidget(right_splitter)
        outer_splitter.setSizes([450, 950])

        main_layout.addWidget(outer_splitter)

        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)
        self._status_bar.showMessage("Starting…")

    def _setup_tray(self):
        self._tray = QSystemTrayIcon(self)
        self._tray.setIcon(self.style().standardIcon(
            self.style().StandardPixmap.SP_MessageBoxWarning
        ))
        self._tray.setToolTip("CodeQL Chrome")
        if self._tray.isSystemTrayAvailable():
            self._tray.show()

    def _notify(self, title: str, message: str):
        if self._tray and self._tray.isSystemTrayAvailable():
            self._tray.showMessage(
                title, message,
                QSystemTrayIcon.MessageIcon.Warning, 8000,
            )

    def _load_persisted_findings(self):
        if self._store.count > 0:
            self._findings_panel.load_findings(self._store.findings)
            self._toolbar.set_status(self._store.summary_text(), "#3498db")
        # Watch findings.json for external changes (CLI writes)
        self._file_watcher = QFileSystemWatcher(self)
        if os.path.isfile(self._store._path):
            self._file_watcher.addPath(self._store._path)
        self._file_watcher.fileChanged.connect(self._on_findings_file_changed)

    def _on_findings_file_changed(self, path: str):
        """findings.json was modified externally — reload."""
        old_count = self._store.count
        self._store._findings.clear()
        self._store._seen.clear()
        self._store._load()
        self._findings_panel.load_findings(self._store.findings)
        new_count = self._store.count
        if new_count > old_count:
            added = new_count - old_count
            self._toolbar.set_status(self._store.summary_text(), "#e74c3c")
            self._notify(
                "CodeQL: New Findings",
                f"{added} new finding{'s' if added != 1 else ''}. "
                f"Total: {self._store.summary_text()}",
            )
        elif new_count > 0:
            self._toolbar.set_status(self._store.summary_text(), "#3498db")
        else:
            self._toolbar.set_status("Findings cleared", "#27ae60")
        # Re-add path to watcher (some OS remove it after change)
        if os.path.isfile(path) and path not in self._file_watcher.files():
            self._file_watcher.addPath(path)

    def _check_prerequisites(self):
        prereqs = verify_prerequisites()
        self._codeql_ready = bool(prereqs.get("codeql"))
        missing = [k for k, v in prereqs.items() if not v]
        if missing:
            self._toolbar.set_status(
                f"Missing: {', '.join(missing)}", "#e74c3c"
            )
        elif self._store.count == 0:
            self._toolbar.set_status("Ready", "#27ae60")

    def _get_setting(self, key: str, default: str = "") -> str:
        return QSettings("CodeQLChrome", "CodeQLChrome").value(key, default)

    # ── Automatic startup ──

    def _auto_start(self):
        if codeql_is_installed() or find_codeql():
            self._codeql_ready = True
            self._auto_launch_chrome()
        else:
            self._start_codeql_setup(then_launch=True)

    def _auto_launch_chrome(self):
        chrome_path = self._get_setting("chrome_path") or find_chrome()
        if not chrome_path:
            self._toolbar.set_status("Chrome not found", "#e74c3c")
            return
        port = int(self._get_setting("cdp_port", "9222") or 9222)

        self._launcher = ChromeLauncher(chrome_path=chrome_path, cdp_port=port)
        self._launch_worker = ChromeLaunchWorker(self._launcher)
        self._launch_worker.progress.connect(self._on_progress)
        self._launch_worker.launched.connect(self._on_chrome_launched_auto)
        self._launch_worker.error.connect(self._on_error)
        self._launch_worker.start()
        self._toolbar.set_status("Launching Chrome…", "#f39c12")

    def _on_chrome_launched_auto(self, ws_url: str):
        self._browser_ws_url = ws_url
        self._toolbar.set_status("Chrome running — auto-capturing", "#27ae60")
        self._status_bar.showMessage(f"CDP: {ws_url}")
        self._auto_start_capture()

    def _auto_start_capture(self):
        if not self._launcher:
            return
        self._script_count = 0
        self._capture_worker = CaptureWorker(cdp_port=self._launcher.cdp_port)
        self._capture_worker.script_captured.connect(self._on_script_captured)
        self._capture_worker.context_created.connect(self._on_context_created)
        self._capture_worker.context_destroyed.connect(self._on_context_destroyed)
        self._capture_worker.error.connect(self._on_error)
        self._capture_worker.chrome_died.connect(self._on_chrome_died)
        self._capture_worker.start()

        self._toolbar.set_state_capturing()
        self._toolbar.set_status("Capturing scripts… (0)", "#3498db")

    # ── CodeQL Auto-Setup ──

    def _start_codeql_setup(self, then_launch: bool = False):
        self._setup_then_launch = then_launch
        self._setup_worker = CodeQLSetupWorker()
        self._setup_worker.progress.connect(self._on_progress)
        self._setup_worker.finished_setup.connect(self._on_codeql_setup_done)
        self._setup_worker.error.connect(self._on_codeql_setup_error)
        self._setup_worker.start()
        self._toolbar.set_status("Setting up CodeQL…", "#f39c12")

    def _on_codeql_setup_done(self, codeql_path: str):
        self._codeql_ready = True
        self._toolbar.set_status("CodeQL ready", "#27ae60")
        self._status_bar.showMessage(f"CodeQL installed: {codeql_path}")
        self._check_prerequisites()
        if self._setup_then_launch:
            self._setup_then_launch = False
            self._auto_launch_chrome()

    def _on_codeql_setup_error(self, msg: str):
        self._toolbar.set_status("CodeQL setup failed — analysis disabled", "#e74c3c")
        self._status_bar.showMessage(f"CodeQL setup error: {msg}")
        QMessageBox.warning(
            self, "CodeQL Setup Failed",
            f"CodeQL could not be installed:\n\n{msg}\n\n"
            "Chrome will launch but analysis is disabled.\n"
            "Fix in Settings or download manually from:\n"
            "https://github.com/github/codeql-action/releases",
        )
        if self._setup_then_launch:
            self._setup_then_launch = False
            self._auto_launch_chrome()

    # ── Manual Launch Chrome ──

    def _on_launch(self):
        chrome_path = self._get_setting("chrome_path") or find_chrome()
        port = int(self._get_setting("cdp_port", "9222") or 9222)
        if not chrome_path:
            QMessageBox.critical(
                self, "Error",
                "Chrome not found. Configure path in Settings.",
            )
            return
        self._launcher = ChromeLauncher(chrome_path=chrome_path, cdp_port=port)
        self._launch_worker = ChromeLaunchWorker(self._launcher)
        self._launch_worker.progress.connect(self._on_progress)
        self._launch_worker.launched.connect(self._on_chrome_launched_manual)
        self._launch_worker.error.connect(self._on_error)
        self._launch_worker.start()
        self._toolbar.set_status("Launching Chrome…", "#f39c12")

    def _on_chrome_launched_manual(self, ws_url: str):
        self._browser_ws_url = ws_url
        self._toolbar.set_state_chrome_running()
        self._toolbar.set_status("Chrome running — ready to capture", "#27ae60")
        self._status_bar.showMessage(f"CDP: {ws_url}")

    # ── Capture ──

    def _on_capture(self):
        if not self._launcher:
            return
        self._auto_start_capture()

    def _on_script_captured(self, info: ScriptInfo):
        self._script_count += 1
        self._toolbar.set_status(
            f"Capturing scripts… ({self._script_count})", "#3498db"
        )
        self._status_bar.showMessage(f"Captured: {info.display_name}")

        # Debounce: schedule analysis for this script's context
        ctx_key = info.context_key
        if ctx_key:
            self._schedule_analysis(ctx_key)

    def _on_context_created(self, info: ContextInfo):
        self._status_bar.showMessage(f"Context: {info.label}")

    def _on_context_destroyed(self, context_key: str):
        # Flush pending debounce — submit to daemon immediately since
        # the context is closing and no more scripts will arrive
        timer = self._debounce_timers.pop(context_key, None)
        if timer and timer.isActive():
            timer.stop()
            self._on_debounce_fired(context_key)
        # Remove from capture client
        if self._capture_worker:
            self._capture_worker.remove_context(context_key)

    def _on_stop_capture(self):
        if self._capture_worker:
            self._capture_worker.stop_capture()
            self._capture_worker.wait(3000)
        self._toolbar.set_status(
            f"Capture stopped — {self._script_count} scripts", "#27ae60"
        )

    def _on_chrome_died(self):
        self._status_bar.showMessage("Chrome closed")
        # Cancel all debounce timers
        for timer in self._debounce_timers.values():
            timer.stop()
        self._debounce_timers.clear()

        if self._spider_worker:
            self._spider_worker.stop()
            self._spider_worker.wait(2000)
            self._spider_worker = None

        if self._capture_worker:
            self._capture_worker.stop_capture()
            self._capture_worker.wait(2000)
            self._capture_worker = None

        self._script_count = 0
        self._browser_ws_url = ""

        self._toolbar.set_state_idle()
        self._toolbar.set_status("Chrome closed — ready to relaunch", "#f39c12")

    # ── Spider ──

    def _on_spider(self):
        if not self._capture_worker:
            return
        pc = self._capture_worker.get_page_client()
        if not pc:
            QMessageBox.warning(self, "No Page", "No page target connected.")
            return

        config = SpiderConfig(
            scope="same-origin",
            max_depth=3,
            max_pages=50,
            wait_after_load=4.0,
        )
        self._spider_worker = SpiderWorker(page_client=pc, config=config)
        # Get current page URL as start URL
        targets = self._launcher.get_page_targets() if self._launcher else []
        start_url = targets[0].get("url", "") if targets else ""
        if not start_url or start_url == "about:blank":
            QMessageBox.warning(
                self, "No URL",
                "Navigate to a page first, then start the spider.",
            )
            return

        self._spider_worker.set_start_url(start_url)
        self._spider_worker.page_started.connect(self._on_spider_page)
        self._spider_worker.page_done.connect(self._on_spider_page_done)
        self._spider_worker.finished_crawl.connect(self._on_spider_done)
        self._spider_worker.error.connect(self._on_error)
        self._spider_worker.start()

        self._toolbar.set_state_spidering()
        self._toolbar.set_status(f"Spidering: {start_url}", "#9b59b6")

    def _on_spider_page(self, url: str, depth: int):
        self._status_bar.showMessage(f"Spider [{depth}]: {url}")

    def _on_spider_page_done(self, result):
        self._toolbar.set_status(
            f"Spider: {result.url} — {result.links_found} links", "#9b59b6"
        )

    def _on_stop_spider(self):
        if self._spider_worker:
            self._spider_worker.stop()
            self._spider_worker.wait(5000)
            self._spider_worker = None
        self._toolbar.set_state_capturing()
        self._toolbar.set_status("Spider stopped", "#27ae60")

    def _on_spider_done(self, total: int):
        self._spider_worker = None
        self._toolbar.set_state_capturing()
        self._toolbar.set_status(f"Spider done — {total} pages visited", "#27ae60")

    # ── Debounced Auto-Analysis via Daemon ──

    def _ensure_daemon(self):
        if self._daemon and self._daemon.is_running:
            return
        codeql_path = self._get_setting("codeql_path") or find_codeql()
        if not codeql_path:
            return
        self._daemon = CodeQLDaemon(
            store=self._store,
            codeql_path=codeql_path,
            on_progress=lambda msg: QTimer.singleShot(
                0, lambda m=msg: self._on_progress(m)
            ),
            on_findings=lambda ck, fl: QTimer.singleShot(
                0, lambda c=ck, f=fl: self._on_daemon_findings(c, f)
            ),
        )
        self._daemon.start()

    def _schedule_analysis(self, context_key: str):
        """Reset the debounce timer for a context. When it fires (no new
        scripts for ANALYSIS_DEBOUNCE_SECS), submit to the daemon if the
        content hash has changed."""
        if context_key in self._debounce_timers:
            self._debounce_timers[context_key].stop()

        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.setInterval(int(ANALYSIS_DEBOUNCE_SECS * 1000))
        timer.timeout.connect(lambda ck=context_key: self._on_debounce_fired(ck))
        self._debounce_timers[context_key] = timer
        timer.start()

    def _on_debounce_fired(self, context_key: str):
        self._debounce_timers.pop(context_key, None)

        if not self._capture_worker or not self._codeql_ready:
            return

        scripts = self._capture_worker.get_context_scripts(context_key)
        if not scripts:
            return

        h = content_hash(scripts)
        if self._analyzed_hashes.get(context_key) == h:
            return
        self._analyzed_hashes[context_key] = h

        ci = self._capture_worker.get_context_info(context_key)
        label = ci.label if ci else context_key

        self._ensure_daemon()
        if self._daemon:
            self._daemon.submit(context_key, dict(scripts), label)
            self._status_bar.showMessage(
                f"Queued for analysis: {label} "
                f"({self._daemon.queue_size} in queue)"
            )

    def _on_daemon_findings(self, context_key: str, findings: list):
        """Called by the daemon (via QTimer.singleShot) when analysis completes."""
        self._findings_panel.load_findings(self._store.findings)

        if self._store.count > 0:
            self._toolbar.set_status(self._store.summary_text(), "#e74c3c")
        else:
            self._toolbar.set_status("No findings", "#27ae60")

        if findings:
            self._notify(
                "CodeQL: Security Findings Detected",
                f"{len(findings)} new. Total: {self._store.summary_text()}",
            )

    # ── Clear Findings ──

    def _on_clear_findings(self):
        self._store.clear()
        self._analyzed_hashes.clear()
        self._findings_panel.clear()
        self._trace_panel.clear()
        self._source_panel.clear()
        self._toolbar.set_status("Findings cleared", "#27ae60")

    # ── Selection ──

    def _resolve_path(self, file_path: str, source_root: str) -> str:
        if source_root and not os.path.isabs(file_path):
            return os.path.normpath(os.path.join(source_root, file_path))
        return os.path.normpath(file_path)

    def _on_finding_selected(self, finding: Finding):
        self._trace_panel.show_finding(finding)

        file_path = self._resolve_path(finding.file_path, finding.source_root)

        trace_lines = []
        for flow in finding.code_flows:
            for step in flow:
                sp = self._resolve_path(step.file_path, finding.source_root)
                if sp == file_path:
                    trace_lines.append(step.start_line)

        self._source_panel.highlight_finding(
            file_path, finding.start_line, trace_lines
        )

    def _on_trace_step_selected(self, step: TraceStep):
        source_root = ""
        if self._findings_panel._findings:
            idx = self._findings_panel._tree.currentIndex()
            if idx.isValid():
                item = self._findings_panel._model.item(idx.row(), 0)
                if item:
                    finding = item.data(Qt.UserRole)
                    if finding:
                        source_root = finding.source_root

        file_path = self._resolve_path(step.file_path, source_root)
        self._source_panel.highlight_finding(file_path, step.start_line)

    # ── Common ──

    def _on_progress(self, msg: str):
        self._status_bar.showMessage(msg)

    def _on_error(self, msg: str):
        self._toolbar.set_status("Error", "#e74c3c")
        QMessageBox.critical(self, "Error", msg)

    def _on_settings(self):
        dlg = SettingsDialog(self)
        if dlg.exec() == QDialog.Accepted:
            self._check_prerequisites()

    # ── Cleanup ──

    def closeEvent(self, event):
        for timer in self._debounce_timers.values():
            timer.stop()
        if self._spider_worker:
            self._spider_worker.stop()
            self._spider_worker.wait(2000)
        if self._daemon:
            self._daemon.stop()
        if self._capture_worker:
            self._capture_worker.stop_capture()
            self._capture_worker.wait(2000)
        if self._launcher:
            self._launcher.shutdown()
        if self._tray:
            self._tray.hide()
        event.accept()
