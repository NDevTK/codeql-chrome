import os
import re
import tempfile
from urllib.parse import urlparse

from app.cdp_client import ScriptInfo


class ScriptStore:
    def __init__(self, base_dir: str | None = None):
        self._base_dir = base_dir or tempfile.mkdtemp(prefix="codeql_js_src_")
        self._map: dict[str, str] = {}        # script_id → abs file_path
        self._rel_map: dict[str, str] = {}    # script_id → rel file_path
        self._reverse: dict[str, ScriptInfo] = {}  # rel_path → ScriptInfo

    @property
    def base_dir(self) -> str:
        return self._base_dir

    @property
    def file_map(self) -> dict[str, str]:
        return dict(self._map)

    @property
    def file_count(self) -> int:
        return len(self._map)

    def reverse_lookup(self, rel_path: str) -> ScriptInfo | None:
        norm = os.path.normpath(rel_path)
        return self._reverse.get(norm)

    def save_script(self, info: ScriptInfo) -> str:
        if not info.source or not info.source.strip():
            return ""

        rel_path = self._url_to_path(info)
        full_path = os.path.normpath(os.path.join(self._base_dir, rel_path))

        # Path traversal check — ensure file stays inside base_dir
        if not full_path.startswith(os.path.normpath(self._base_dir) + os.sep):
            safe_id = re.sub(r"[^\w]", "_", info.script_id)
            rel_path = os.path.join("_safe", f"{safe_id}.js")
            full_path = os.path.join(self._base_dir, rel_path)

        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(info.source)

        self._map[info.script_id] = full_path
        self._rel_map[info.script_id] = rel_path
        self._reverse[os.path.normpath(rel_path)] = info
        return full_path

    def save_all(self, scripts: dict[str, ScriptInfo]) -> str:
        for info in scripts.values():
            self.save_script(info)
        return self._base_dir

    def get_path(self, script_id: str) -> str | None:
        return self._map.get(script_id)

    def _url_to_path(self, info: ScriptInfo) -> str:
        if info.is_dynamic or not info.url:
            safe_id = re.sub(r"[^\w]", "_", info.script_id)
            return os.path.join("_dynamic", f"vm_{safe_id}.js")

        parsed = urlparse(info.url)
        host = parsed.hostname or "_unknown"
        path = parsed.path.lstrip("/")

        if not path:
            path = "index.js"
        if not path.endswith(".js"):
            line = info.start_line
            path = re.sub(r"\.[^.]+$", "", path) + f"_inline_L{line}.js"

        parts = [self._sanitize(host)]
        for part in path.split("/"):
            s = self._sanitize(part)
            if s in (".", ".."):
                s = "_"
            parts.append(s)

        return os.path.join(*parts)

    @staticmethod
    def _sanitize(name: str) -> str:
        name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
        name = name.strip(". ")
        name = name[:200]
        return name or "_"

    def cleanup(self):
        import shutil
        if os.path.isdir(self._base_dir):
            shutil.rmtree(self._base_dir, ignore_errors=True)
