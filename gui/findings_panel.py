import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QHeaderView,
    QLineEdit,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from app.config import SEVERITY_COLORS
from app.sarif_parser import Finding


class FindingsPanel(QWidget):
    finding_selected = Signal(object)  # Finding

    COLUMNS = [
        "Severity", "Rule", "Message",
        "Script URL", "Page Context",
        "File", "Line",
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._findings: list[Finding] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("Filter findings…")
        self._filter_edit.textChanged.connect(self._apply_filter)
        layout.addWidget(self._filter_edit)

        self._model = QStandardItemModel()
        self._model.setHorizontalHeaderLabels(self.COLUMNS)

        self._tree = QTreeView()
        self._tree.setModel(self._model)
        self._tree.setRootIsDecorated(False)
        self._tree.setAlternatingRowColors(True)
        self._tree.setSortingEnabled(True)
        self._tree.setSelectionBehavior(QTreeView.SelectRows)
        self._tree.clicked.connect(self._on_clicked)

        header = self._tree.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Severity
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Rule
        header.setSectionResizeMode(2, QHeaderView.Stretch)           # Message
        header.setSectionResizeMode(3, QHeaderView.Interactive)       # Script URL
        header.setSectionResizeMode(4, QHeaderView.Interactive)       # Page Context
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # File
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)  # Line
        header.resizeSection(3, 220)
        header.resizeSection(4, 220)

        layout.addWidget(self._tree)

    def load_findings(self, findings: list[Finding]):
        self._findings = findings
        self._model.removeRows(0, self._model.rowCount())

        for finding in findings:
            sev_item = QStandardItem(finding.severity)
            color = SEVERITY_COLORS.get(finding.severity, "#888")
            sev_item.setForeground(QBrush(QColor(color)))
            sev_item.setData(finding, Qt.UserRole)

            rule_item = QStandardItem(finding.rule_id)
            msg_item = QStandardItem(finding.message)

            url_item = QStandardItem(finding.script_url)
            url_item.setToolTip(finding.script_url)

            ctx_item = QStandardItem(finding.page_context)
            ctx_item.setToolTip(finding.page_context)

            file_item = QStandardItem(os.path.basename(finding.file_path))
            file_item.setToolTip(finding.file_path)
            line_item = QStandardItem(str(finding.start_line))

            for item in (sev_item, rule_item, msg_item, url_item,
                         ctx_item, file_item, line_item):
                item.setEditable(False)

            self._model.appendRow([
                sev_item, rule_item, msg_item, url_item,
                ctx_item, file_item, line_item,
            ])

    def remove_by_context(self, context_key: str):
        """Remove findings belonging to a destroyed context."""
        rows_to_remove = []
        for row in range(self._model.rowCount()):
            item = self._model.item(row, 0)
            if not item:
                continue
            finding = item.data(Qt.UserRole)
            if finding and finding.context_key == context_key:
                rows_to_remove.append(row)
        # Remove from bottom up so indices stay valid
        for row in reversed(rows_to_remove):
            self._model.removeRow(row)
        self._findings = [
            f for f in self._findings if f.context_key != context_key
        ]

    def _on_clicked(self, index):
        row = index.row()
        item = self._model.item(row, 0)
        if item:
            finding = item.data(Qt.UserRole)
            if finding:
                self.finding_selected.emit(finding)

    def _apply_filter(self, text: str):
        text = text.lower()
        for row in range(self._model.rowCount()):
            match = False
            for col in range(self._model.columnCount()):
                item = self._model.item(row, col)
                if item and text in item.text().lower():
                    match = True
                    break
            self._tree.setRowHidden(row, self._tree.rootIndex(), not match)

    def clear(self):
        self._findings.clear()
        self._model.removeRows(0, self._model.rowCount())
