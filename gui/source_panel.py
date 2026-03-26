import os
import re

from PySide6.QtCore import QRect, QSize, Qt
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QPainter,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextCursor,
)
from PySide6.QtWidgets import QLabel, QPlainTextEdit, QVBoxLayout, QWidget


class JavaScriptHighlighter(QSyntaxHighlighter):
    KEYWORDS = (
        "break|case|catch|class|const|continue|debugger|default|delete|do|else|"
        "export|extends|finally|for|function|if|import|in|instanceof|let|new|"
        "return|super|switch|this|throw|try|typeof|var|void|while|with|yield|"
        "async|await|of|from|static|get|set"
    )

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rules = []

        kw_fmt = QTextCharFormat()
        kw_fmt.setForeground(QColor("#c678dd"))
        kw_fmt.setFontWeight(QFont.Bold)
        self._rules.append((re.compile(rf"\b({self.KEYWORDS})\b"), kw_fmt))

        str_fmt = QTextCharFormat()
        str_fmt.setForeground(QColor("#98c379"))
        self._rules.append((re.compile(r'"[^"\\]*(\\.[^"\\]*)*"'), str_fmt))
        self._rules.append((re.compile(r"'[^'\\]*(\\.[^'\\]*)*'"), str_fmt))
        self._rules.append((re.compile(r"`[^`\\]*(\\.[^`\\]*)*`"), str_fmt))

        num_fmt = QTextCharFormat()
        num_fmt.setForeground(QColor("#d19a66"))
        self._rules.append((re.compile(r"\b\d+(\.\d+)?\b"), num_fmt))

        comment_fmt = QTextCharFormat()
        comment_fmt.setForeground(QColor("#5c6370"))
        comment_fmt.setFontItalic(True)
        self._rules.append((re.compile(r"//[^\n]*"), comment_fmt))
        self._rules.append((re.compile(r"/\*.*?\*/", re.DOTALL), comment_fmt))

    def highlightBlock(self, text: str):
        for pattern, fmt in self._rules:
            for match in pattern.finditer(text):
                self.setFormat(match.start(), match.end() - match.start(), fmt)


class LineNumberArea(QWidget):
    def __init__(self, editor):
        super().__init__(editor)
        self._editor = editor

    def sizeHint(self):
        return QSize(self._editor.line_number_area_width(), 0)

    def paintEvent(self, event):
        self._editor.line_number_area_paint(event)


class CodeEditor(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.Monospace)
        self.setFont(font)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.setTabStopDistance(QFontMetrics(font).horizontalAdvance(" ") * 4)

        self._line_number_area = LineNumberArea(self)
        self.blockCountChanged.connect(self._update_line_number_width)
        self.updateRequest.connect(self._update_line_number_area)
        self._update_line_number_width(0)

        self._highlighter = JavaScriptHighlighter(self.document())
        self._highlight_lines: dict[int, QColor] = {}

    def line_number_area_width(self) -> int:
        digits = max(1, len(str(self.blockCount())))
        return 10 + self.fontMetrics().horizontalAdvance("9") * digits

    def _update_line_number_width(self, _):
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def _update_line_number_area(self, rect, dy):
        if dy:
            self._line_number_area.scroll(0, dy)
        else:
            self._line_number_area.update(0, rect.y(), self._line_number_area.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self._update_line_number_width(0)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self._line_number_area.setGeometry(
            QRect(cr.left(), cr.top(), self.line_number_area_width(), cr.height())
        )

    def line_number_area_paint(self, event):
        painter = QPainter(self._line_number_area)
        painter.fillRect(event.rect(), QColor("#2b2b2b"))

        block = self.firstVisibleBlock()
        block_num = block.blockNumber()
        top = int(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + int(self.blockBoundingRect(block).height())

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                painter.setPen(QColor("#636d83"))
                painter.drawText(
                    0, top, self._line_number_area.width() - 5,
                    self.fontMetrics().height(),
                    Qt.AlignRight, str(block_num + 1),
                )
            block = block.next()
            top = bottom
            bottom = top + int(self.blockBoundingRect(block).height())
            block_num += 1
        painter.end()

    def set_highlight_lines(self, lines: dict[int, QColor]):
        self._highlight_lines = lines
        self._apply_highlights()

    def _apply_highlights(self):
        from PySide6.QtWidgets import QTextEdit
        selections = []
        for line_num, color in self._highlight_lines.items():
            block = self.document().findBlockByLineNumber(line_num - 1)
            if not block.isValid():
                continue
            sel = QTextEdit.ExtraSelection()
            sel.format.setBackground(color)
            sel.format.setProperty(QTextCharFormat.FullWidthSelection, True)
            sel.cursor = QTextCursor(block)
            selections.append(sel)
        self.setExtraSelections(selections)

    def goto_line(self, line: int):
        block = self.document().findBlockByLineNumber(line - 1)
        if block.isValid():
            cursor = QTextCursor(block)
            self.setTextCursor(cursor)
            self.centerCursor()


class SourcePanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._title = QLabel("Source Code")
        self._title.setStyleSheet("font-weight: bold; padding: 4px;")
        layout.addWidget(self._title)

        self._editor = CodeEditor()
        layout.addWidget(self._editor)

        self._current_file = ""

    def load_file(self, file_path: str):
        if not os.path.isfile(file_path):
            # File gone (temp dir cleaned up) — handled by show_snippet
            self._editor.setPlainText(f"Source file not available: {file_path}")
            self._title.setText("Source Code — file not on disk")
            self._current_file = ""
            return

        self._current_file = file_path
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        self._editor.setPlainText(content)
        self._title.setText(f"Source Code — {os.path.basename(file_path)}")
        self._title.setToolTip(file_path)

    def highlight_line(self, line: int, color: QColor = None):
        if color is None:
            color = QColor(255, 255, 0, 60)
        self._editor.set_highlight_lines({line: color})
        self._editor.goto_line(line)

    def highlight_finding(self, file_path: str, line: int,
                          trace_lines: list[int] | None = None):
        if file_path != self._current_file:
            self.load_file(file_path)

        highlights = {line: QColor(255, 80, 80, 80)}
        if trace_lines:
            for tl in trace_lines:
                if tl != line:
                    highlights[tl] = QColor(255, 255, 0, 50)

        self._editor.set_highlight_lines(highlights)
        self._editor.goto_line(line)

    def clear(self):
        self._editor.setPlainText("")
        self._editor.set_highlight_lines({})
        self._title.setText("Source Code")
        self._current_file = ""
