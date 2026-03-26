from PySide6.QtCore import Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QLabel, QToolBar, QWidget


class AnalysisToolbar(QToolBar):
    spider_requested = Signal()
    stop_spider_requested = Signal()
    clear_findings_requested = Signal()
    settings_requested = Signal()

    def __init__(self, parent=None):
        super().__init__("Main Toolbar", parent)
        self.setMovable(False)

        self._spider_action = QAction("Spider", self)
        self._spider_action.setToolTip("Crawl links from the current page")
        self._spider_action.setEnabled(False)
        self._spider_action.triggered.connect(self.spider_requested)
        self.addAction(self._spider_action)

        self._stop_spider_action = QAction("Stop Spider", self)
        self._stop_spider_action.setToolTip("Stop the spider crawl")
        self._stop_spider_action.setEnabled(False)
        self._stop_spider_action.triggered.connect(self.stop_spider_requested)
        self.addAction(self._stop_spider_action)

        self.addSeparator()

        self._clear_action = QAction("Clear Findings", self)
        self._clear_action.setToolTip("Clear all persisted findings")
        self._clear_action.triggered.connect(self.clear_findings_requested)
        self.addAction(self._clear_action)

        self.addSeparator()

        self._settings_action = QAction("Settings", self)
        self._settings_action.triggered.connect(self.settings_requested)
        self.addAction(self._settings_action)

        spacer = QWidget()
        spacer.setFixedWidth(20)
        self.addWidget(spacer)

        self._status_label = QLabel("Starting…")
        self._status_label.setStyleSheet("color: #888; padding: 0 8px;")
        self.addWidget(self._status_label)

    def set_status(self, text: str, color: str = "#888"):
        self._status_label.setText(text)
        self._status_label.setStyleSheet(f"color: {color}; padding: 0 8px;")

    def set_state_starting(self):
        self._spider_action.setEnabled(False)
        self._stop_spider_action.setEnabled(False)

    def set_state_ready(self):
        self._spider_action.setEnabled(True)
        self._stop_spider_action.setEnabled(False)

    def set_state_spidering(self):
        self._spider_action.setEnabled(False)
        self._stop_spider_action.setEnabled(True)
