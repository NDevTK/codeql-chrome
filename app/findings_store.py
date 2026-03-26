"""Centralized findings store — shared by GUI and CLI.

Persists to a JSON file on disk. Both GUI and CLI read/write the same file.
Findings survive across sessions until the user explicitly clears them.
"""
import json
import os

from app.sarif_parser import Finding, TraceStep

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_STORE_PATH = os.path.join(_PROJECT_ROOT, "findings.json")


class FindingsStore:
    def __init__(self, path: str | None = None):
        self._path = path or DEFAULT_STORE_PATH
        self._findings: list[Finding] = []
        self._seen: set[str] = set()
        self._load()

    @property
    def findings(self) -> list[Finding]:
        return list(self._findings)

    @property
    def count(self) -> int:
        return len(self._findings)

    def add(self, findings: list[Finding]):
        """Add findings, deduplicating against existing ones."""
        added = False
        for f in findings:
            if f.dedup_key in self._seen:
                continue
            self._seen.add(f.dedup_key)
            self._findings.append(f)
            added = True
        if added:
            self._sort()
            self._save()

    def remove_by_context(self, context_key: str):
        """Remove all findings for a destroyed context."""
        removed_keys = {
            f.dedup_key for f in self._findings
            if f.context_key == context_key
        }
        if not removed_keys:
            return
        self._findings = [
            f for f in self._findings if f.context_key != context_key
        ]
        self._seen -= removed_keys
        self._save()

    def clear(self):
        self._findings.clear()
        self._seen.clear()
        self._save()
        self._clear_sources()

    def _clear_sources(self):
        """Remove all persisted source files."""
        from app.workers import SOURCES_DIR
        if os.path.isdir(SOURCES_DIR):
            import shutil
            shutil.rmtree(SOURCES_DIR, ignore_errors=True)

    def _sort(self):
        self._findings.sort(key=lambda f: (
            {"High": 0, "Medium": 1, "Low": 2, "Info": 3}.get(f.severity, 4),
            f.file_path,
            f.start_line,
        ))

    # ── Persistence ──

    def _save(self):
        data = [self._finding_to_dict(f) for f in self._findings]
        try:
            with open(self._path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except OSError:
            pass

    def _load(self):
        if not os.path.isfile(self._path):
            return
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for entry in data:
                f = self._dict_to_finding(entry)
                if f.dedup_key not in self._seen:
                    self._seen.add(f.dedup_key)
                    self._findings.append(f)
        except (OSError, json.JSONDecodeError, KeyError):
            pass

    @staticmethod
    def _finding_to_dict(f: Finding) -> dict:
        return {
            "rule_id": f.rule_id,
            "severity": f.severity,
            "message": f.message,
            "file_path": f.file_path,
            "start_line": f.start_line,
            "end_line": f.end_line,
            "source_root": f.source_root,
            "script_url": f.script_url,
            "page_context": f.page_context,
            "context_key": f.context_key,
            "code_flows": [
                [
                    {
                        "file_path": s.file_path,
                        "start_line": s.start_line,
                        "start_column": s.start_column,
                        "end_line": s.end_line,
                        "end_column": s.end_column,
                        "message": s.message,
                    }
                    for s in flow
                ]
                for flow in f.code_flows
            ],
        }

    @staticmethod
    def _dict_to_finding(d: dict) -> Finding:
        code_flows = []
        for flow_data in d.get("code_flows", []):
            steps = [
                TraceStep(
                    file_path=s["file_path"],
                    start_line=s["start_line"],
                    start_column=s.get("start_column", 0),
                    end_line=s.get("end_line", s["start_line"]),
                    end_column=s.get("end_column", 0),
                    message=s.get("message", ""),
                )
                for s in flow_data
            ]
            if steps:
                code_flows.append(steps)

        return Finding(
            rule_id=d["rule_id"],
            severity=d["severity"],
            message=d["message"],
            file_path=d["file_path"],
            start_line=d["start_line"],
            end_line=d.get("end_line", 0),
            code_flows=code_flows,
            source_root=d.get("source_root", ""),
            script_url=d.get("script_url", ""),
            page_context=d.get("page_context", ""),
            context_key=d.get("context_key", ""),
        )

    # ── Stats ──

    def summary(self) -> dict[str, int]:
        s = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self._findings:
            s[f.severity] = s.get(f.severity, 0) + 1
        s["total"] = len(self._findings)
        return s

    def summary_text(self) -> str:
        s = self.summary()
        n = s["total"]
        if n == 0:
            return "No findings."
        parts = []
        for sev in ["High", "Medium", "Low", "Info"]:
            if s[sev]:
                parts.append(f"{s[sev]} {sev}")
        return f"{n} finding{'s' if n != 1 else ''} ({', '.join(parts)})"

    # ── Export ──

    def to_json(self) -> list[dict]:
        return [
            {
                "rule": f.rule_id,
                "severity": f.severity,
                "message": f.message,
                "script_url": f.script_url,
                "file": f.file_path,
                "line": f.start_line,
                "context": f.page_context,
                "trace": [
                    {"file": s.file_path, "line": s.start_line, "message": s.message}
                    for flow in f.code_flows for s in flow
                ] if f.code_flows else [],
            }
            for f in self._findings
        ]

    def to_sarif(self) -> dict:
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                       "master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL Chrome Analyzer", "version": "1.0.0"}},
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": {"High": "error", "Medium": "warning",
                                  "Low": "note", "Info": "none"}.get(f.severity, "warning"),
                        "message": {"text": f.message},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {"startLine": f.start_line,
                                       "endLine": f.end_line or f.start_line},
                        }}],
                    }
                    for f in self._findings
                ],
            }],
        }

    def write_sarif(self, path: str):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_sarif(), fh, indent=2)

    def write_json(self, path: str):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_json(), fh, indent=2)

    def format_text(self) -> str:
        if not self._findings:
            return "No findings.\n"
        lines = []
        by_sev: dict[str, list[Finding]] = {}
        for f in self._findings:
            by_sev.setdefault(f.severity, []).append(f)
        for sev in ["High", "Medium", "Low", "Info"]:
            group = by_sev.get(sev, [])
            if not group:
                continue
            lines.append(f"\n{'='*60}")
            lines.append(f" {sev} ({len(group)})")
            lines.append(f"{'='*60}")
            for f in group:
                lines.append(f"\n  Rule:    {f.rule_id}")
                lines.append(f"  Message: {f.message}")
                lines.append(f"  Script:  {f.script_url or f.file_path}")
                lines.append(f"  Line:    {f.start_line}")
                lines.append(f"  Context: {f.page_context}")
                lines.append(f"  Source:  {f.source_root}")
                if f.code_flows:
                    flow = f.code_flows[0]
                    lines.append(f"  Trace:   {len(flow)} steps")
                    for i, step in enumerate(flow):
                        tag = ("Source" if i == 0
                               else "Sink" if i == len(flow) - 1
                               else f"  {i+1}")
                        lines.append(
                            f"    [{tag:>6}] "
                            f"{os.path.basename(step.file_path)}:{step.start_line}"
                            f"  {step.message}"
                        )
        lines.append(f"\n{self.summary_text()}")
        return "\n".join(lines) + "\n"
