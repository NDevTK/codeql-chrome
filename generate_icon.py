"""Generate the app icon — a shield with a code bracket and magnifying glass."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PySide6.QtCore import Qt, QRect, QPoint
from PySide6.QtGui import (
    QColor, QFont, QFontMetrics, QIcon, QImage, QPainter, QPainterPath,
    QPen, QLinearGradient, QRadialGradient, QBrush,
)
from PySide6.QtWidgets import QApplication

def generate_icon(size: int = 256) -> QImage:
    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(Qt.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing, True)

    cx, cy = size / 2, size / 2
    m = size / 256  # scale factor

    # Shield shape
    shield = QPainterPath()
    shield.moveTo(cx, 10 * m)
    shield.cubicTo(cx - 90 * m, 10 * m, 10 * m, 30 * m, 10 * m, 60 * m)
    shield.lineTo(10 * m, 160 * m)
    shield.cubicTo(10 * m, 210 * m, cx - 30 * m, 240 * m, cx, 250 * m)
    shield.cubicTo(cx + 30 * m, 240 * m, 246 * m, 210 * m, 246 * m, 160 * m)
    shield.lineTo(246 * m, 60 * m)
    shield.cubicTo(246 * m, 30 * m, cx + 90 * m, 10 * m, cx, 10 * m)
    shield.closeSubpath()

    # Shield gradient — dark blue
    grad = QLinearGradient(cx, 10 * m, cx, 250 * m)
    grad.setColorAt(0.0, QColor(30, 60, 120))
    grad.setColorAt(1.0, QColor(15, 30, 70))
    p.setBrush(QBrush(grad))
    p.setPen(QPen(QColor(80, 140, 220), 3 * m))
    p.drawPath(shield)

    # Inner shield highlight
    inner = QPainterPath()
    inner.moveTo(cx, 24 * m)
    inner.cubicTo(cx - 76 * m, 24 * m, 26 * m, 40 * m, 26 * m, 66 * m)
    inner.lineTo(26 * m, 156 * m)
    inner.cubicTo(26 * m, 200 * m, cx - 24 * m, 228 * m, cx, 236 * m)
    inner.cubicTo(cx + 24 * m, 228 * m, 230 * m, 200 * m, 230 * m, 156 * m)
    inner.lineTo(230 * m, 66 * m)
    inner.cubicTo(230 * m, 40 * m, cx + 76 * m, 24 * m, cx, 24 * m)
    inner.closeSubpath()

    inner_grad = QLinearGradient(cx, 24 * m, cx, 236 * m)
    inner_grad.setColorAt(0.0, QColor(35, 75, 140))
    inner_grad.setColorAt(1.0, QColor(20, 40, 85))
    p.setBrush(QBrush(inner_grad))
    p.setPen(Qt.NoPen)
    p.drawPath(inner)

    # Code brackets "{ }" in the center
    bracket_font = QFont("Consolas", int(72 * m))
    bracket_font.setBold(True)
    p.setFont(bracket_font)
    p.setPen(QPen(QColor(100, 200, 255), 2 * m))

    fm = QFontMetrics(bracket_font)
    text = "{ }"
    text_rect = fm.boundingRect(text)
    tx = cx - text_rect.width() / 2
    ty = cy + text_rect.height() / 4 - 10 * m
    p.drawText(int(tx), int(ty), text)

    # Small magnifying glass in bottom-right
    glass_cx = cx + 58 * m
    glass_cy = cy + 55 * m
    glass_r = 22 * m

    # Glass circle
    p.setPen(QPen(QColor(220, 180, 50), 3.5 * m))
    p.setBrush(QBrush(QColor(220, 180, 50, 30)))
    p.drawEllipse(int(glass_cx - glass_r), int(glass_cy - glass_r),
                  int(glass_r * 2), int(glass_r * 2))

    # Glass handle
    handle_pen = QPen(QColor(220, 180, 50), 4 * m, Qt.SolidLine, Qt.RoundCap)
    p.setPen(handle_pen)
    hx = glass_cx + glass_r * 0.7
    hy = glass_cy + glass_r * 0.7
    p.drawLine(int(hx), int(hy), int(hx + 18 * m), int(hy + 18 * m))

    p.end()
    return img


def save_icons():
    app = QApplication.instance() or QApplication(sys.argv)

    sizes = [16, 32, 48, 64, 128, 256]
    os.makedirs("icons", exist_ok=True)

    for s in sizes:
        img = generate_icon(s)
        path = f"icons/icon_{s}.png"
        img.save(path)
        print(f"Saved {path}")

    # Also save the 256 as the main icon
    img = generate_icon(256)
    img.save("icons/icon.png")
    print("Saved icons/icon.png")

    # Generate .ico with multiple sizes
    try:
        from PIL import Image
        images = []
        for s in sizes:
            images.append(Image.open(f"icons/icon_{s}.png"))
        images[0].save("icons/icon.ico", format="ICO",
                       append_images=images[1:], sizes=[(s, s) for s in sizes])
        print("Saved icons/icon.ico")
    except ImportError:
        print("PIL not available — skipping .ico generation")


if __name__ == "__main__":
    save_icons()
