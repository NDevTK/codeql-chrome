#!/usr/bin/env python3
"""CodeQL Chrome — JavaScript Security Analyzer.

    python main.py                           # Launch GUI
    python main.py https://example.com       # CLI headless analysis
    python main.py --help                    # CLI help
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    # If URLs are passed (any arg not starting with --), run CLI mode
    has_urls = any(
        a for a in sys.argv[1:]
        if not a.startswith("-") and ("." in a or ":" in a)
    )

    if has_urls or "--help" in sys.argv or "-h" in sys.argv:
        from cli import main as cli_main
        sys.exit(cli_main())
    else:
        _run_gui()


def _run_gui():
    from app.cleanup import cleanup_stale_temp_dirs

    removed = cleanup_stale_temp_dirs()
    if removed:
        print(f"Startup cleanup: removed {removed} stale temp dir(s)")

    from PySide6.QtWidgets import QApplication
    from PySide6.QtGui import QIcon, QPalette, QColor

    app = QApplication(sys.argv)
    app.setApplicationName("CodeQL Chrome")
    app.setOrganizationName("CodeQLChrome")
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(43, 43, 43))
    palette.setColor(QPalette.WindowText, QColor(212, 212, 212))
    palette.setColor(QPalette.Base, QColor(30, 30, 30))
    palette.setColor(QPalette.AlternateBase, QColor(38, 38, 38))
    palette.setColor(QPalette.ToolTipBase, QColor(50, 50, 50))
    palette.setColor(QPalette.ToolTipText, QColor(212, 212, 212))
    palette.setColor(QPalette.Text, QColor(212, 212, 212))
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, QColor(212, 212, 212))
    palette.setColor(QPalette.BrightText, QColor(255, 51, 51))
    palette.setColor(QPalette.Link, QColor(86, 156, 214))
    palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    palette.setColor(QPalette.Disabled, QPalette.Text, QColor(128, 128, 128))
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(128, 128, 128))
    app.setPalette(palette)

    icon_path = os.path.join(os.path.dirname(__file__), "icons", "icon.png")
    if os.path.isfile(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    from gui.main_window import MainWindow
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
