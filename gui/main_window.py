import os

from PySide6.QtCore import Qt, QFileSystemWatcher, QSettings, QTimer, Signal
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
from app.codeql_daemon import CodeQLDaemon
from app.codeql_setup import is_installed as codeql_is_installed
from app.config import find_chrome, find_codeql, verify_prerequisites
from app.findings_store import FindingsStore
from app.sarif_parser import Finding, TraceStep
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
    # Signals for thread-safe daemon callbacks
    _daemon_progress = Signal(str)
    _daemon_findings_signal = Signal(str, list)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("CodeQL Chrome — JavaScript Security Analyzer")
        self.resize(1400, 850)

        self._launcher: ChromeLauncher | None = None
        self._capture_worker: CaptureWorker | None = None
        self._setup_worker: CodeQLSetupWorker | None = None
        self._spider_worker: SpiderWorker | None = None
        self._store = FindingsStore()
        self._daemon: CodeQLDaemon | None = None
        self._script_count = 0
        self._codeql_ready = False
        self._setup_then_launch = False

        self._debounce_timers: dict[str, QTimer] = {}  # context_key → timer
        self._analyzed_content: set[str] = set()  # content hashes already analyzed
        self._last_notified_count = 0

        self._setup_ui()
        self._setup_tray()
        self._load_persisted_findings()

        # Connect daemon signals (thread-safe cross-thread communication)
        self._daemon_progress.connect(self._on_progress)
        self._daemon_findings_signal.connect(self._on_daemon_findings)

        QTimer.singleShot(100, self._auto_start)

    # ── UI ──

    def _setup_ui(self):
        self._toolbar = AnalysisToolbar(self)
        self.addToolBar(self._toolbar)

        self._toolbar.spider_toggled.connect(self._on_spider_toggled)
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
        icon_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "icons", "icon.png",
        )
        if os.path.isfile(icon_path):
            from PySide6.QtGui import QIcon
            self._tray.setIcon(QIcon(icon_path))
        else:
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
        self._last_notified_count = self._store.count
        # Watch findings.json for external changes (CLI writes)
        self._file_watcher = QFileSystemWatcher(self)
        if os.path.isfile(self._store._path):
            self._file_watcher.addPath(self._store._path)
        self._file_watcher.fileChanged.connect(self._on_findings_file_changed)

    def _on_findings_file_changed(self, path: str):
        old_count = self._store.count
        self._store._findings.clear()
        self._store._seen.clear()
        self._store._load()
        self._findings_panel.load_findings(self._store.findings)
        new_count = self._store.count
        if new_count > old_count:
            self._toolbar.set_status(self._store.summary_text(), "#e74c3c")
            self._notify(
                "CodeQL: New Findings",
                f"{new_count - old_count} new. Total: {self._store.summary_text()}",
            )
        elif new_count > 0:
            self._toolbar.set_status(self._store.summary_text(), "#3498db")
        else:
            self._toolbar.set_status("Findings cleared", "#27ae60")
        if os.path.isfile(path) and path not in self._file_watcher.files():
            self._file_watcher.addPath(path)

    def _get_setting(self, key: str, default: str = "") -> str:
        return QSettings("CodeQLChrome", "CodeQLChrome").value(key, default)

    # ── Startup: CodeQL → Chrome → Capture (all automatic) ──

    def _auto_start(self):
        if codeql_is_installed() or find_codeql():
            self._codeql_ready = True
            self._launch_chrome()
        else:
            self._setup_then_launch = True
            self._setup_worker = CodeQLSetupWorker()
            self._setup_worker.progress.connect(self._on_progress)
            self._setup_worker.finished_setup.connect(self._on_codeql_ready)
            self._setup_worker.error.connect(self._on_codeql_setup_error)
            self._setup_worker.start()
            self._toolbar.set_status("Setting up CodeQL…", "#f39c12")

    def _on_codeql_ready(self, codeql_path: str):
        self._codeql_ready = True
        self._status_bar.showMessage(f"CodeQL: {codeql_path}")
        if self._setup_then_launch:
            self._setup_then_launch = False
            self._launch_chrome()

    def _on_codeql_setup_error(self, msg: str):
        self._toolbar.set_status("CodeQL setup failed", "#e74c3c")
        QMessageBox.warning(
            self, "CodeQL Setup Failed",
            f"CodeQL could not be installed:\n\n{msg}\n\n"
            "Analysis is disabled. Fix in Settings or download from:\n"
            "https://github.com/github/codeql-action/releases",
        )
        if self._setup_then_launch:
            self._setup_then_launch = False
            self._launch_chrome()

    def _launch_chrome(self):
        chrome_path = self._get_setting("chrome_path") or find_chrome()
        port = int(self._get_setting("cdp_port", "9222") or 9222)

        if not chrome_path:
            self._toolbar.set_status("Chrome not found", "#e74c3c")
            return

        try:
            self._launcher = ChromeLauncher(chrome_path=chrome_path, cdp_port=port)
            worker = ChromeLaunchWorker(self._launcher)
            worker.progress.connect(self._on_progress)
            worker.launched.connect(self._on_chrome_ready)
            worker.error.connect(self._on_error)
            self._launch_worker = worker
            worker.start()
            self._toolbar.set_status("Launching Chrome…", "#f39c12")
        except Exception as e:
            self._on_error(str(e))

    def _on_chrome_ready(self, ws_url: str):
        self._status_bar.showMessage(f"CDP: {ws_url}")
        self._start_capture()

    def _start_capture(self):
        if not self._launcher:
            return
        self._script_count = 0
        self._capture_worker = CaptureWorker(cdp_port=self._launcher.cdp_port)
        self._capture_worker.script_captured.connect(self._on_script_captured)
        self._capture_worker.context_created.connect(self._on_context_created)
        self._capture_worker.context_destroyed.connect(self._on_context_destroyed)
        self._capture_worker.chrome_died.connect(self._on_chrome_died)
        self._capture_worker.error.connect(self._on_error)
        self._capture_worker.start()

        self._toolbar.set_state_ready()
        self._toolbar.set_status(
            self._store.summary_text() if self._store.count > 0 else "Ready",
            "#e74c3c" if self._store.count > 0 else "#27ae60",
        )

    # ── Script capture ──

    def _on_script_captured(self, info: ScriptInfo):
        self._script_count += 1
        self._status_bar.showMessage(f"Captured: {info.display_name}")
        if info.context_key:
            self._schedule_analysis(info.context_key)

    def _on_context_created(self, info: ContextInfo):
        self._status_bar.showMessage(f"Context: {info.label}")

    def _on_context_destroyed(self, context_key: str):
        timer = self._debounce_timers.pop(context_key, None)
        if timer and timer.isActive():
            timer.stop()
            self._on_debounce_fired(context_key)
        if self._capture_worker:
            self._capture_worker.remove_context(context_key)

    def _on_chrome_died(self):
        self._status_bar.showMessage("Chrome closed")
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
        self._toolbar.set_state_starting()
        self._toolbar.set_status("Chrome closed", "#f39c12")

    # ── Spider ──

    def _on_spider_toggled(self, checked: bool):
        if checked:
            self._start_spider()
        else:
            self._stop_spider()

    def _start_spider(self):
        if not self._capture_worker:
            self._toolbar.set_state_ready()
            return
        pc = self._capture_worker.get_page_client()
        if not pc:
            QMessageBox.warning(self, "Spider", "No page target connected.")
            self._toolbar.set_state_ready()
            return

        try:
            result = pc.evaluate("location.href")
            start_url = result.get("result", {}).get("value", "")
        except Exception:
            start_url = ""
        if not start_url or start_url in ("about:blank", "chrome://newtab/"):
            QMessageBox.warning(
                self, "Spider",
                "Navigate to a page first, then start the spider.",
            )
            self._toolbar.set_state_ready()
            return

        config = SpiderConfig(
            scope="same-origin",
            max_depth=3,
            max_pages=50,
            wait_after_load=4.0,
        )
        self._spider_worker = SpiderWorker(page_client=pc, config=config)
        self._spider_worker.set_start_url(start_url)
        self._spider_worker.page_started.connect(self._on_spider_page)
        self._spider_worker.page_done.connect(self._on_spider_page_done)
        self._spider_worker.finished_crawl.connect(self._on_spider_done)
        self._spider_worker.error.connect(self._on_error)
        self._spider_worker.start()

        self._toolbar.set_state_spidering()
        self._toolbar.set_status(f"Spidering: {start_url}", "#9b59b6")

    def _on_spider_page(self, url: str, depth: int):
        self._toolbar.set_status(f"Spider [{depth}]: {url[:60]}", "#9b59b6")
        self._status_bar.showMessage(f"Navigating: {url}")

    def _on_spider_page_done(self, result):
        self._status_bar.showMessage(
            f"{result.url} — {result.links_found} links ({result.status})"
        )

    def _stop_spider(self):
        if self._spider_worker:
            self._spider_worker.stop()
            self._spider_worker.wait(5000)
            self._spider_worker = None
        self._toolbar.set_state_ready()
        self._toolbar.set_status("Spider stopped", "#27ae60")

    def _on_spider_done(self, total: int):
        self._spider_worker = None
        self._toolbar.set_state_ready()
        self._toolbar.set_status(f"Spider done — {total} pages", "#27ae60")

    # ── Auto-analysis via daemon ──

    def _ensure_daemon(self):
        if self._daemon and self._daemon.is_running:
            return
        codeql_path = self._get_setting("codeql_path") or find_codeql()
        if not codeql_path:
            return
        self._daemon = CodeQLDaemon(
            store=self._store,
            codeql_path=codeql_path,
            on_progress=lambda msg: self._daemon_progress.emit(msg),
            on_findings=lambda ck, fl: self._daemon_findings_signal.emit(ck, fl),
        )
        self._daemon.start()

    def _schedule_analysis(self, context_key: str):
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
        if h in self._analyzed_content:
            return
        self._analyzed_content.add(h)
        ci = self._capture_worker.get_context_info(context_key)
        label = ci.label if ci else context_key
        self._ensure_daemon()
        if self._daemon:
            self._daemon.submit(context_key, dict(scripts), label)
            self._status_bar.showMessage(
                f"Queued: {label} ({self._daemon.queue_size} in queue)"
            )

    def _on_daemon_findings(self, context_key: str, findings: list):
        old_count = self._last_notified_count
        self._findings_panel.load_findings(self._store.findings)
        new_count = self._store.count
        if new_count > 0:
            self._toolbar.set_status(self._store.summary_text(), "#e74c3c")
        else:
            self._toolbar.set_status("No findings", "#27ae60")
        added = new_count - old_count
        if added > 0:
            self._last_notified_count = new_count
            self._notify(
                "CodeQL: Security Findings Detected",
                f"{added} new. Total: {self._store.summary_text()}",
            )

    # ── Clear ──

    def _on_clear_findings(self):
        self._store.clear()
        self._analyzed_content.clear()
        self._last_notified_count = 0
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
            pass

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
