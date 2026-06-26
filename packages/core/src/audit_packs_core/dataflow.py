from __future__ import annotations
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class DataFlow:
    source_line: int
    source_type: str
    transforms: tuple[str, ...]
    sink_line: int
    sink_type: str
    has_transform: bool


_PYTHON_SOURCE_PATTERNS = [
    # request.form, request.data, request.json
    (re.compile(r"\brequest\.(form|data|json)\b"), "user_input"),
    # input() calls
    (re.compile(r"\binput\s*\("), "user_input"),
    # os.environ
    (re.compile(r"\bos\.environ\b"), "env_var"),
    # ORM .get() / .filter() on known models
    (re.compile(r"\b(User|Patient|Customer)\.(get|filter|filter_by)\s*\("), "db_read"),
]

_PYTHON_TRANSFORM_NAMES = {"encrypt", "mask", "hash", "anonymise", "redact", "bcrypt"}

_PYTHON_SINK_PATTERNS = [
    (re.compile(r"\bdb\.session\.add\s*\("), "db_write"),
    (re.compile(r"\b\w+\.save\s*\(\s*\)"), "db_write"),
    (re.compile(r"\brequests\.(post|put)\s*\("), "api_call"),
    (re.compile(r"\blogging\.(info|warning|error|debug|critical)\s*\("), "log"),
    (re.compile(r"\bprint\s*\("), "log"),
    (re.compile(r"\bresponse\.json\s*\("), "response"),
]

_HCL_SOURCE_PATTERN = re.compile(r'\bvar\.\w+|\bdata\s+"aws_secretsmanager_secret"')
_HCL_TRANSFORM_PATTERN = re.compile(r"\bkms_key_id\s*=|\bencrypted\s*=\s*true")
_HCL_SINK_PATTERN = re.compile(
    r'\bresource\s+"(aws_s3_bucket_object|aws_rds_cluster|aws_lambda_function)"'
)


def _extract_python_flows(text: str) -> list[DataFlow]:
    lines = text.splitlines()
    flows: list[DataFlow] = []

    sources: list[tuple[int, str]] = []
    sinks: list[tuple[int, str]] = []
    transform_lines: list[int] = []

    for i, line in enumerate(lines, start=1):
        for pattern, src_type in _PYTHON_SOURCE_PATTERNS:
            if pattern.search(line):
                sources.append((i, src_type))
                break

        for name in _PYTHON_TRANSFORM_NAMES:
            if re.search(rf"\b{name}\s*\(", line):
                transform_lines.append(i)
                break

        for pattern, sink_type in _PYTHON_SINK_PATTERNS:
            if pattern.search(line):
                sinks.append((i, sink_type))
                break

    for src_line, src_type in sources:
        for sink_line, sink_type in sinks:
            if sink_line <= src_line:
                continue
            transforms_between = tuple(
                _name
                for _name in _PYTHON_TRANSFORM_NAMES
                for t_line in transform_lines
                if src_line < t_line < sink_line
                and re.search(rf"\b{_name}\s*\(", lines[t_line - 1])
            )
            has_transform = bool(transforms_between) or any(
                src_line < t < sink_line for t in transform_lines
            )
            flows.append(
                DataFlow(
                    source_line=src_line,
                    source_type=src_type,
                    transforms=transforms_between,
                    sink_line=sink_line,
                    sink_type=sink_type,
                    has_transform=has_transform,
                )
            )

    return flows


def _extract_hcl_flows(text: str) -> list[DataFlow]:
    lines = text.splitlines()
    sources: list[int] = []
    sinks: list[int] = []
    has_transform = False

    for i, line in enumerate(lines, start=1):
        if _HCL_SOURCE_PATTERN.search(line):
            sources.append(i)
        if _HCL_TRANSFORM_PATTERN.search(line):
            has_transform = True
        if _HCL_SINK_PATTERN.search(line):
            sinks.append(i)

    flows = []
    for src in sources:
        for sink in sinks:
            if sink > src:
                flows.append(
                    DataFlow(
                        source_line=src,
                        source_type="env_var",
                        transforms=(),
                        sink_line=sink,
                        sink_type="db_write",
                        has_transform=has_transform,
                    )
                )
    return flows


def extract_data_flows(file_text: str, language: str) -> list[DataFlow]:
    """Extract source→transform→sink chains. language: 'python'|'hcl'|'yaml'|'json'."""
    if language == "python":
        return _extract_python_flows(file_text)
    if language in ("hcl", "yaml", "json"):
        return _extract_hcl_flows(file_text)
    return []


def flow_confidence(flows: list[DataFlow], finding_line: int) -> float:
    """
    Compute flow_confidence score for finding at finding_line.

    Returns 0.5 (neutral) when no flows are within ±50 lines.
    Among in-range flows, selects closest to finding_line (tie-break: prefer has_transform=False).
    Classification:
      has_transform=False, both ends in range  → 0.9
      has_transform=False, one end in range    → 0.7
      has_transform=True,  both ends in range  → 0.2
      has_transform=True,  one end in range    → 0.5
    """
    RANGE = 50

    def in_range(line: int) -> bool:
        return abs(line - finding_line) <= RANGE

    in_range_flows = [
        f for f in flows if in_range(f.source_line) or in_range(f.sink_line)
    ]

    if not in_range_flows:
        return 0.5

    def sort_key(f: DataFlow) -> tuple:
        dist = min(abs(f.source_line - finding_line), abs(f.sink_line - finding_line))
        return (dist, 0 if not f.has_transform else 1)

    best = sorted(in_range_flows, key=sort_key)[0]
    both_in_range = in_range(best.source_line) and in_range(best.sink_line)

    if not best.has_transform:
        return 0.9 if both_in_range else 0.7
    else:
        return 0.2 if both_in_range else 0.5
