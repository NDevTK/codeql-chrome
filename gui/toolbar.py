from PySide6.QtCore import Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QLabel, QToolBar, QWidget


class AnalysisToolbar(QToolBar):
    spider_toggled = Signal(bool)  # True = start, False = stop
    clear_findings_requested = Signal()
    settings_requested = Signal()

    def __init__(self, parent=None):
        super().__init__("Main Toolbar", parent)
        self.setMovable(False)

        self._spider_action = QAction("Spider", self)
        self._spider_action.setToolTip("Crawl links from the current page")
        self._spider_action.setCheckable(True)
        self._spider_action.setEnabled(False)
        self._spider_action.toggled.connect(self.spider_toggled)
        self.addAction(self._spider_action)

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

    def set_state_ready(self):
        self._spider_action.setEnabled(True)
        # Uncheck without emitting the signal
        self._spider_action.blockSignals(True)
        self._spider_action.setChecked(False)
        self._spider_action.blockSignals(False)

    def set_state_spidering(self):
        self._spider_action.setEnabled(True)
        self._spider_action.blockSignals(True)
        self._spider_action.setChecked(True)
        self._spider_action.blockSignals(False)
