import json
import os
import platform
import shutil
import tarfile
import tempfile
import urllib.request

_GITHUB_API = "https://api.github.com/repos/github/codeql-action/releases/latest"

_BUNDLE_ASSETS = {
    ("Windows", "AMD64"): "codeql-bundle-win64.tar.gz",
    ("Windows", "x86_64"): "codeql-bundle-win64.tar.gz",
    ("Linux", "x86_64"): "codeql-bundle-linux64.tar.gz",
    ("Linux", "aarch64"): "codeql-bundle-linux64.tar.gz",
    ("Darwin", "x86_64"): "codeql-bundle-osx64.tar.gz",
    ("Darwin", "arm64"): "codeql-bundle-osx64.tar.gz",
}

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CODEQL_DIR = os.path.join(_PROJECT_ROOT, "codeql")
CODEQL_EXE = os.path.join(CODEQL_DIR, "codeql.exe" if os.name == "nt" else "codeql")


def is_installed() -> bool:
    return os.path.isfile(CODEQL_EXE)


def get_bundle_url(on_progress=None) -> str:
    """Resolve the download URL for the latest CodeQL bundle from GitHub."""
    system = platform.system()
    machine = platform.machine()
    asset_name = _BUNDLE_ASSETS.get((system, machine))
    if not asset_name:
        raise RuntimeError(
            f"No CodeQL bundle available for {system}/{machine}. "
            "Download manually from https://github.com/github/codeql-action/releases"
        )

    if on_progress:
        on_progress("Resolving latest CodeQL version…")

    req = urllib.request.Request(
        _GITHUB_API,
        headers={"User-Agent": "CodeQL-Chrome-Analyzer/1.0"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())

    for asset in data.get("assets", []):
        if asset["name"] == asset_name:
            tag = data.get("tag_name", "unknown")
            if on_progress:
                on_progress(f"Latest CodeQL: {tag}")
            return asset["browser_download_url"]

    raise RuntimeError(
        f"Asset '{asset_name}' not found in latest release. "
        "Download manually from https://github.com/github/codeql-action/releases"
    )


def download_and_install(on_progress=None) -> str:
    """Download the CodeQL bundle and extract to project_root/codeql/.
    Returns the path to the codeql executable.
    """
    if is_installed():
        if on_progress:
            on_progress("CodeQL already installed")
        return CODEQL_EXE

    url = get_bundle_url(on_progress)

    if on_progress:
        on_progress("Downloading CodeQL bundle…")

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".tar.gz")
    os.close(tmp_fd)

    try:
        _download_file(url, tmp_path, on_progress)

        if on_progress:
            on_progress("Extracting CodeQL bundle (this may take a minute)…")

        # The tarball contains a top-level "codeql/" directory
        extract_dir = os.path.dirname(CODEQL_DIR)

        # Remove partial install if present
        if os.path.isdir(CODEQL_DIR):
            shutil.rmtree(CODEQL_DIR)

        with tarfile.open(tmp_path, "r:gz") as tar:
            tar.extractall(path=extract_dir)

        if not os.path.isfile(CODEQL_EXE):
            raise FileNotFoundError(
                f"Extraction succeeded but {CODEQL_EXE} not found. "
                "The bundle structure may have changed."
            )

        if on_progress:
            on_progress("CodeQL installed successfully")

        return CODEQL_EXE

    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _download_file(url: str, dest: str, on_progress=None):
    """Download url to dest with progress reporting.  Follows redirects."""
    req = urllib.request.Request(url, headers={"User-Agent": "CodeQL-Chrome-Analyzer/1.0"})

    with urllib.request.urlopen(req, timeout=300) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        chunk_size = 1024 * 256  # 256 KB

        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)

                if on_progress and total > 0:
                    pct = downloaded * 100 // total
                    mb = downloaded / (1024 * 1024)
                    total_mb = total / (1024 * 1024)
                    on_progress(f"Downloading… {mb:.0f} / {total_mb:.0f} MB ({pct}%)")
