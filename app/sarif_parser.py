import json
from dataclasses import dataclass, field

from app.config import SEVERITY_MAP


@dataclass
class TraceStep:
    file_path: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    message: str

    @property
    def location_str(self) -> str:
        return f"{self.file_path}:{self.start_line}"


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file_path: str
    start_line: int
    end_line: int = 0
    code_flows: list[list[TraceStep]] = field(default_factory=list)
    source_root: str = ""     # base dir to resolve file_path (permanent sources/ dir)
    script_url: str = ""      # original URL of the script
    page_context: str = ""    # human label
    context_key: str = ""     # machine key for grouping

    @property
    def location_str(self) -> str:
        return f"{self.file_path}:{self.start_line}"

    @property
    def dedup_key(self) -> str:
        return f"{self.rule_id}|{self.file_path}|{self.start_line}|{self.message}"


class SarifParser:
    def __init__(self, source_root: str = ""):
        self._source_root = source_root

    def parse(self, sarif_path: str) -> list[Finding]:
        with open(sarif_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        findings = []
        seen: set[str] = set()
        for run in data.get("runs", []):
            for result in run.get("results", []):
                finding = self._parse_result(result)
                if not finding:
                    continue
                if finding.dedup_key in seen:
                    continue
                seen.add(finding.dedup_key)
                findings.append(finding)

        findings.sort(key=lambda f: (
            {"High": 0, "Medium": 1, "Low": 2, "Info": 3}.get(f.severity, 4),
            f.file_path,
            f.start_line,
        ))
        return findings

    def _parse_result(self, result: dict) -> Finding | None:
        rule_id = result.get("ruleId", "unknown")
        level = result.get("level", "warning")
        severity = SEVERITY_MAP.get(level, "Medium")
        message = result.get("message", {}).get("text", "")

        locations = result.get("locations", [])
        if not locations:
            return None

        phys = locations[0].get("physicalLocation", {})
        artifact = phys.get("artifactLocation", {})
        file_path = self._resolve_uri(artifact.get("uri", ""))
        region = phys.get("region", {})
        start_line = region.get("startLine", 0)
        end_line = region.get("endLine", start_line)

        code_flows = []
        for cf in result.get("codeFlows", []):
            for tf in cf.get("threadFlows", []):
                steps = []
                for loc_wrapper in tf.get("locations", []):
                    step = self._parse_trace_location(loc_wrapper)
                    if step:
                        steps.append(step)
                if steps:
                    code_flows.append(steps)

        return Finding(
            rule_id=rule_id,
            severity=severity,
            message=message,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            code_flows=code_flows,
            source_root=self._source_root,
        )

    def _parse_trace_location(self, loc_wrapper: dict) -> TraceStep | None:
        loc = loc_wrapper.get("location", {})
        phys = loc.get("physicalLocation", {})
        artifact = phys.get("artifactLocation", {})
        uri = artifact.get("uri", "")
        region = phys.get("region", {})

        if not uri:
            return None

        return TraceStep(
            file_path=self._resolve_uri(uri),
            start_line=region.get("startLine", 0),
            start_column=region.get("startColumn", 0),
            end_line=region.get("endLine", region.get("startLine", 0)),
            end_column=region.get("endColumn", 0),
            message=loc.get("message", {}).get("text", ""),
        )

    def _resolve_uri(self, uri: str) -> str:
        if uri.startswith("file:///"):
            uri = uri[8:]
        elif uri.startswith("file://"):
            uri = uri[7:]
        uri = uri.replace("/", "\\") if "\\" in self._source_root else uri
        return uri
