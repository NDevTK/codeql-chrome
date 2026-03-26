import os

from PySide6.QtCore import Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QLabel, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from app.sarif_parser import Finding, TraceStep


class TracePanel(QWidget):
    step_selected = Signal(object)  # TraceStep

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._title = QLabel("Dataflow Trace")
        self._title.setStyleSheet("font-weight: bold; padding: 4px;")
        layout.addWidget(self._title)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Step", "Location", "Description"])
        self._tree.setColumnWidth(0, 60)
        self._tree.setColumnWidth(1, 250)
        self._tree.setAlternatingRowColors(True)
        self._tree.itemClicked.connect(self._on_item_clicked)
        layout.addWidget(self._tree)

    def show_finding(self, finding: Finding):
        self._tree.clear()

        if not finding.code_flows:
            self._title.setText("Dataflow Trace (no trace available)")
            item = QTreeWidgetItem(self._tree, ["", "", finding.message])
            item.setForeground(2, QColor("#888"))
            return

        self._title.setText(
            f"Dataflow Trace — {len(finding.code_flows)} flow(s)"
        )

        for flow_idx, flow in enumerate(finding.code_flows):
            flow_item = QTreeWidgetItem(
                self._tree,
                [f"Flow {flow_idx + 1}", "", f"{len(flow)} steps"],
            )
            flow_item.setExpanded(True)

            for step_idx, step in enumerate(flow):
                label = "Source" if step_idx == 0 else (
                    "Sink" if step_idx == len(flow) - 1 else str(step_idx + 1)
                )
                loc = f"{os.path.basename(step.file_path)}:{step.start_line}"
                desc = step.message or ""

                child = QTreeWidgetItem(flow_item, [label, loc, desc])
                child.setData(0, 0x0100, step)  # Qt.UserRole
                child.setToolTip(1, step.file_path)

                if step_idx == 0:
                    child.setForeground(0, QColor("#27ae60"))
                elif step_idx == len(flow) - 1:
                    child.setForeground(0, QColor("#e74c3c"))

    def _on_item_clicked(self, item: QTreeWidgetItem, column: int):
        step = item.data(0, 0x0100)
        if isinstance(step, TraceStep):
            self.step_selected.emit(step)

    def clear(self):
        self._tree.clear()
        self._title.setText("Dataflow Trace")
