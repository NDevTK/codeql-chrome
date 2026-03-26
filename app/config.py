import os
import shutil

CHROME_PATHS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
]

CDP_PORT = 9222

# Client-side-only queries — no server-side Node.js rules.
# 24 queries vs 104 in javascript-security-extended.qls.
CLIENT_SIDE_QUERIES = [
    # DOM XSS
    "Security/CWE-079/Xss.ql",
    "Security/CWE-079/XssThroughDom.ql",
    "Security/CWE-079/UnsafeJQueryPlugin.ql",
    "Security/CWE-079/UnsafeHtmlConstruction.ql",
    "Security/CWE-079/ReflectedXss.ql",
    "Security/CWE-079/StoredXss.ql",
    # Code injection (eval, Function, setTimeout string)
    "Security/CWE-094/CodeInjection.ql",
    "Security/CWE-094/UnsafeCodeConstruction.ql",
    "Security/CWE-094/UnsafeDynamicMethodAccess.ql",
    # Client-side URL redirect
    "Security/CWE-601/ClientSideUrlRedirect.ql",
    # Client-side request forgery
    "Security/CWE-918/ClientSideRequestForgery.ql",
    # postMessage
    "Security/CWE-020/MissingOriginCheck.ql",
    "Security/CWE-201/PostMessageStar.ql",
    # Sanitization issues
    "Security/CWE-116/BadTagFilter.ql",
    "Security/CWE-116/IncompleteHtmlAttributeSanitization.ql",
    "Security/CWE-116/IncompleteSanitization.ql",
    # Tainted conditions
    "Security/CWE-807/ConditionalBypass.ql",
    "Security/CWE-843/TypeConfusionThroughParameterTampering.ql",
    # Untrusted script sources
    "Security/CWE-830/FunctionalityFromUntrustedDomain.ql",
    "Security/CWE-830/FunctionalityFromUntrustedSource.ql",
    # Client-side crypto
    "Security/CWE-338/InsecureRandomness.ql",
    # Prototype pollution
    "Security/CWE-915/PrototypePollutingAssignment.ql",
    "Security/CWE-915/PrototypePollutingMergeCall.ql",
    # Cookie exposure
    "Security/CWE-1004/ClientExposedCookie.ql",
]

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
