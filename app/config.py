import os
import shutil

CHROME_PATHS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
]

CDP_PORT = 9222

CODEQL_QUERY_SUITE = "javascript-security-extended.qls"

SEVERITY_MAP = {
    "error": "High",
    "warning": "Medium",
    "note": "Low",
    "none": "Info",
}

SEVERITY_COLORS = {
    "High": "#e74c3c",
    "Medium": "#e67e22",
    "Low": "#3498db",
    "Info": "#95a5a6",
}


def find_chrome() -> str | None:
    for p in CHROME_PATHS:
        if os.path.isfile(p):
            return p
    return shutil.which("chrome") or shutil.which("google-chrome")


def find_codeql() -> str | None:
    # Check the bundled local install first (auto-downloaded by codeql_setup)
    from app.codeql_setup import CODEQL_EXE
    if os.path.isfile(CODEQL_EXE):
        return CODEQL_EXE

    found = shutil.which("codeql")
    if found:
        return found
    extra = [
        r"D:\codeql\codeql.exe",
        os.path.expanduser(r"~\codeql\codeql.exe"),
    ]
    for p in extra:
        if os.path.isfile(p):
            return os.path.abspath(p)
    return None


def verify_prerequisites() -> dict[str, str | None]:
    return {
        "chrome": find_chrome(),
        "codeql": find_codeql(),
    }
