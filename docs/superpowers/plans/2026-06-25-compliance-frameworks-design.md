# Compliance Framework Extension Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend audit-packs with data-flow analysis, evidence enrichment, a 4-role LLM judge ensemble, composite confidence scoring, CodeQL SARIF ingestion, a detection-agent stub, two new Semgrep rules, confidence badges in PR comments, and updated GitHub Actions inputs.

**Architecture:** The new pipeline branches after diff extraction — `dataflow.py` (pure Python AST/regex) and `evidence.py` (HTTP to GitHub API) run before detection; their outputs feed a composite `FindingScore` computed by `confidence.py`; `adjudicate.py` is rewritten as a sequential 4-role debate (Detector → Verifier‖Adversarial → Judge) returning float scores rather than binary verdicts; `report.py` adds confidence badges and a summary table.

**Tech Stack:** Python 3.11+, pytest, stdlib `ast`/`re`/`dataclasses`/`concurrent.futures`, `PyYAML`, `openai`, `anthropic`, `google-generativeai`, `requests`.

## Global Constraints

- Severity vocabulary: exactly `low`, `medium`, `high`, `critical` — no other values.
- IO boundary: only `engines.py`, `report.py`, and `evidence.py` may make subprocess or HTTP calls.
- All new pure modules (`dataflow.py`, `confidence.py`, `agents.py`) must be testable with `ADJUDICATION_MODE=off` and no network access.
- `packs/` YAML files, `diff.py`, `packs.py`, `coverage.py`, `oscal.py` are unchanged.
- `Finding` additions use default values (`doc_context=""`, `evidence_path=()`) so all existing tests pass without modification.
- License: Apache-2.0. No paid-tier engine features.
- Default `ADJUDICATION_MODE` is `off`; CI runs with no LLM keys configured.
- `pytest -v` must pass with no changes to env after each task.

---

## File Map

| File | Status | Task |
|---|---|---|
| `src/audit_packs/models.py` | Extended | Task 1 |
| `src/audit_packs/dataflow.py` | New | Task 2 |
| `src/audit_packs/evidence.py` | New | Task 3 |
| `src/audit_packs/engines.py` | Extended | Task 4 |
| `src/audit_packs/normalize.py` | Extended | Task 4 |
| `src/audit_packs/confidence.py` | New | Task 5 |
| `src/audit_packs/agents.py` | New | Task 6 |
| `src/audit_packs/adjudicate.py` | Rewritten | Task 7 |
| `audit-models.yaml` | New | Task 7 |
| `rules/pii-fields.yaml` | New | Task 8 |
| `rules/insecure-config.yaml` | New | Task 8 |
| `src/audit_packs/report.py` | Extended | Task 9 |
| `src/audit_packs/cli.py` | Extended | Task 10 |
| `action.yml` | Extended | Task 10 |
| `tests/test_models.py` | Extended | Task 1 |
| `tests/test_dataflow.py` | New | Task 2 |
| `tests/test_evidence.py` | New | Task 3 |
| `tests/test_codeql_normalize.py` | New | Task 4 |
| `tests/test_confidence.py` | New | Task 5 |
| `tests/test_agents.py` | New | Task 6 |
| `tests/test_adjudicate.py` | Rewritten | Task 7 |
| `tests/test_report.py` | Extended | Task 9 |
| `tests/test_cli_frameworks.py` | New | Task 10 |

---

## Task 1: Models Extension

**Files:**
- Modify: `src/audit_packs/models.py`
- Modify: `tests/test_models.py`

**Interfaces:**
- Produces: `PathNode`, updated `Finding` (with `doc_context`, `evidence_path`), `AdjudicationResult`, `AdjudicationMode` — all imported by Tasks 2–10.
- Note: `AdjudicationMode` is defined here and re-exported from `adjudicate.py` for backward compat with existing imports.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_models.py — append these tests
from audit_packs.models import Finding, PathNode, AdjudicationResult, AdjudicationMode, ControlFinding

def test_finding_doc_context_defaults_to_empty():
    f = Finding("CKV_AWS_19", "checkov", "main.tf", 11, "high", "msg", "snippet")
    assert f.doc_context == ""

def test_finding_evidence_path_defaults_to_empty_tuple():
    f = Finding("CKV_AWS_19", "checkov", "main.tf", 11, "high", "msg", "snippet")
    assert f.evidence_path == ()

def test_pathnode_fields():
    pn = PathNode(file="models.py", line=14, snippet="user_id = request.args.get('id')", description="source")
    assert pn.file == "models.py"
    assert pn.line == 14

def test_adjudication_mode_values():
    assert AdjudicationMode.OFF.value == "off"
    assert AdjudicationMode.ADVISORY.value == "advisory"
    assert AdjudicationMode.ENFORCE.value == "enforce"

def test_adjudication_result_fields():
    f = Finding("CKV_AWS_19", "checkov", "main.tf", 11, "high", "msg", "snippet")
    cf = ControlFinding(finding=f, framework="gdpr", control_id="SC-28", control_title="Protection of Information at Rest")
    result = AdjudicationResult(
        control_finding=cf,
        detector_score=0.8,
        verifier_argument="data is stored unencrypted",
        adversarial_argument="this is test infra",
        judge_score=0.75,
        model_consensus=0.75,
        rationale="Evidence supports a real violation.",
    )
    assert result.model_consensus == result.judge_score
    assert result.rationale == "Evidence supports a real violation."
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_models.py -v -k "doc_context or evidence_path or pathnode or adjudication"
```

Expected: FAIL — `PathNode`, `AdjudicationResult`, `AdjudicationMode` not importable from `models`.

- [ ] **Step 3: Implement the model changes**

Replace `src/audit_packs/models.py` with:

```python
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum

SEVERITIES = ("low", "medium", "high", "critical")

def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)

@dataclass(frozen=True)
class PathNode:
    file: str
    line: int
    snippet: str
    description: str

@dataclass(frozen=True)
class Finding:
    check_id: str
    engine: str
    file: str
    line: int
    severity: str
    message: str
    evidence: str
    doc_context: str = ""
    evidence_path: tuple[PathNode, ...] = ()

@dataclass(frozen=True)
class ControlFinding:
    finding: Finding
    framework: str
    control_id: str
    control_title: str

class AssessmentStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    MANUAL = "manual"

class AdjudicationMode(str, Enum):
    OFF = "off"
    ADVISORY = "advisory"
    ENFORCE = "enforce"

@dataclass(frozen=True)
class AdjudicationResult:
    control_finding: ControlFinding
    detector_score: float
    verifier_argument: str
    adversarial_argument: str
    judge_score: float
    model_consensus: float
    rationale: str

@dataclass(frozen=True)
class ControlStatus:
    framework: str
    control_id: str
    control_title: str
    status: AssessmentStatus
    check_ids: tuple
    findings: tuple
    evidence: tuple
```

Also update `adjudicate.py` to re-export `AdjudicationMode` from `models` (backward compat):

```python
# At the top of adjudicate.py, after imports, replace the AdjudicationMode class definition with:
from audit_packs.models import AdjudicationMode  # noqa: F401  (re-export for backward compat)
```

- [ ] **Step 4: Run all tests to verify nothing broke**

```bash
pytest -v
```

Expected: All existing tests PASS. New model tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/audit_packs/models.py tests/test_models.py
git commit -m "feat: add PathNode, AdjudicationResult, AdjudicationMode to models; extend Finding with doc_context and evidence_path"
```

---

## Task 2: DataFlow Module

**Files:**
- Create: `src/audit_packs/dataflow.py`
- Create: `tests/test_dataflow.py`

**Interfaces:**
- Consumes: nothing from other tasks (pure stdlib)
- Produces:
  - `DataFlow` dataclass
  - `extract_data_flows(file_text: str, language: str) -> list[DataFlow]`
  - `flow_confidence(flows: list[DataFlow], finding_line: int) -> float`

- [ ] **Step 1: Write failing tests**

Create `tests/test_dataflow.py`:

```python
from audit_packs.dataflow import DataFlow, extract_data_flows, flow_confidence

PYTHON_WITH_UNPROTECTED_FLOW = """\
def handle_request(request):
    user_data = request.form.get("ssn")
    db.session.add(user_data)
"""

PYTHON_WITH_PROTECTED_FLOW = """\
def handle_request(request):
    user_data = request.form.get("ssn")
    encrypted = encrypt(user_data)
    db.session.add(encrypted)
"""

def test_extract_unprotected_python_flow():
    flows = extract_data_flows(PYTHON_WITH_UNPROTECTED_FLOW, "python")
    assert len(flows) >= 1
    assert any(not f.has_transform for f in flows)

def test_extract_protected_python_flow():
    flows = extract_data_flows(PYTHON_WITH_PROTECTED_FLOW, "python")
    assert any(f.has_transform for f in flows)

def test_extract_unsupported_language_returns_empty():
    flows = extract_data_flows("some code", "ruby")
    assert flows == []

def test_flow_confidence_neutral_when_no_flows():
    assert flow_confidence([], 10) == 0.5

def test_flow_confidence_high_for_unprotected_both_ends_in_range():
    flow = DataFlow(source_line=5, source_type="user_input", transforms=(),
                    sink_line=8, sink_type="db_write", has_transform=False)
    score = flow_confidence([flow], finding_line=6)
    assert score == 0.9

def test_flow_confidence_low_for_protected_both_ends_in_range():
    flow = DataFlow(source_line=5, source_type="user_input", transforms=("encrypt",),
                    sink_line=8, sink_type="db_write", has_transform=True)
    score = flow_confidence([flow], finding_line=6)
    assert score == 0.2

def test_flow_confidence_moderate_for_unprotected_one_end_in_range():
    flow = DataFlow(source_line=5, source_type="user_input", transforms=(),
                    sink_line=200, sink_type="db_write", has_transform=False)
    score = flow_confidence([flow], finding_line=6)
    assert score == 0.7

def test_flow_confidence_neutral_for_protected_one_end_in_range():
    flow = DataFlow(source_line=5, source_type="user_input", transforms=("mask",),
                    sink_line=200, sink_type="db_write", has_transform=True)
    score = flow_confidence([flow], finding_line=6)
    assert score == 0.5

def test_flow_confidence_out_of_range_returns_neutral():
    flow = DataFlow(source_line=500, source_type="user_input", transforms=(),
                    sink_line=600, sink_type="db_write", has_transform=False)
    score = flow_confidence([flow], finding_line=10)
    assert score == 0.5

def test_dataflow_fields():
    flow = DataFlow(source_line=1, source_type="env_var", transforms=("hash",),
                    sink_line=10, sink_type="log", has_transform=True)
    assert flow.has_transform is True
    assert "hash" in flow.transforms
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_dataflow.py -v
```

Expected: FAIL — `audit_packs.dataflow` module not found.

- [ ] **Step 3: Implement `dataflow.py`**

Create `src/audit_packs/dataflow.py`:

```python
from __future__ import annotations
import ast
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
    (re.compile(r'\brequest\.(form|data|json)\b'), "user_input"),
    # input() calls
    (re.compile(r'\binput\s*\('), "user_input"),
    # os.environ
    (re.compile(r'\bos\.environ\b'), "env_var"),
    # ORM .get() / .filter() on known models
    (re.compile(r'\b(User|Patient|Customer)\.(get|filter|filter_by)\s*\('), "db_read"),
]

_PYTHON_TRANSFORM_NAMES = {"encrypt", "mask", "hash", "anonymise", "redact", "bcrypt"}

_PYTHON_SINK_PATTERNS = [
    (re.compile(r'\bdb\.session\.add\s*\('), "db_write"),
    (re.compile(r'\b\w+\.save\s*\(\s*\)'), "db_write"),
    (re.compile(r'\brequests\.(post|put)\s*\('), "api_call"),
    (re.compile(r'\blogging\.(info|warning|error|debug|critical)\s*\('), "log"),
    (re.compile(r'\bprint\s*\('), "log"),
    (re.compile(r'\bresponse\.json\s*\('), "response"),
]

_HCL_SOURCE_PATTERN = re.compile(r'\bvar\.\w+|\bdata\s+"aws_secretsmanager_secret"')
_HCL_TRANSFORM_PATTERN = re.compile(r'\bkms_key_id\s*=|\bencrypted\s*=\s*true')
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
            if re.search(rf'\b{name}\s*\(', line):
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
                _name for _name in _PYTHON_TRANSFORM_NAMES
                for t_line in transform_lines
                if src_line < t_line < sink_line
                and re.search(rf'\b{_name}\s*\(', lines[t_line - 1])
            )
            has_transform = bool(transforms_between) or any(
                src_line < t < sink_line for t in transform_lines
            )
            flows.append(DataFlow(
                source_line=src_line,
                source_type=src_type,
                transforms=transforms_between,
                sink_line=sink_line,
                sink_type=sink_type,
                has_transform=has_transform,
            ))

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
                flows.append(DataFlow(
                    source_line=src,
                    source_type="env_var",
                    transforms=(),
                    sink_line=sink,
                    sink_type="db_write",
                    has_transform=has_transform,
                ))
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
        f for f in flows
        if in_range(f.source_line) or in_range(f.sink_line)
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_dataflow.py -v
```

Expected: All PASS.

- [ ] **Step 5: Run full suite**

```bash
pytest -v
```

Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/audit_packs/dataflow.py tests/test_dataflow.py
git commit -m "feat: add dataflow.py with extract_data_flows() and flow_confidence() scoring"
```

---

## Task 3: Evidence Module

**Files:**
- Create: `src/audit_packs/evidence.py`
- Create: `tests/test_evidence.py`

**Interfaces:**
- Consumes: `Finding` from `models.py` (Task 1)
- Produces:
  - `PRContext(pr_body: str, commit_messages: tuple[str, ...])`
  - `fetch_pr_context(repo: str, pr_number: str, token: str) -> PRContext` — IO boundary
  - `extract_doc_context(file_text: str, line: int) -> str`
  - `enrich(finding: Finding, changed_file_text: str, pr_context: PRContext) -> Finding`
  - `evidence_confidence(finding: Finding, pr_context: PRContext | None) -> float`

- [ ] **Step 1: Write failing tests**

Create `tests/test_evidence.py`:

```python
import dataclasses
import pytest
from unittest.mock import patch, MagicMock
from audit_packs.models import Finding
from audit_packs.evidence import (
    PRContext, extract_doc_context, enrich, evidence_confidence
)

def _finding(**kwargs):
    defaults = dict(check_id="CKV_AWS_19", engine="checkov", file="main.tf",
                    line=5, severity="high", message="msg", evidence="snippet")
    defaults.update(kwargs)
    return Finding(**defaults)

FILE_WITH_DOCSTRING = '''\
# This module handles user data
def store_user(user_id):
    """Stores user PII to the database."""
    db.session.add(user_id)
'''

FILE_WITH_BLOCK_COMMENT = '''\
resource "aws_s3_bucket" "data" {
  # Bucket for sensitive customer records — encryption required by policy
  bucket = "my-bucket"
  encrypted = false
}
'''

def test_extract_doc_context_finds_python_docstring():
    ctx = extract_doc_context(FILE_WITH_DOCSTRING, line=4)
    assert "Stores user PII" in ctx

def test_extract_doc_context_finds_block_comment():
    ctx = extract_doc_context(FILE_WITH_BLOCK_COMMENT, line=4)
    assert "encryption required" in ctx

def test_extract_doc_context_returns_empty_when_none_nearby():
    text = "x = 1\ny = 2\nz = 3\n"
    ctx = extract_doc_context(text, line=2)
    assert ctx == ""

def test_enrich_attaches_doc_context():
    f = _finding(file="main.py", line=4)
    pr = PRContext(pr_body="Refactoring user storage", commit_messages=("fix: update handler",))
    enriched = enrich(f, FILE_WITH_DOCSTRING, pr)
    assert "Stores user PII" in enriched.doc_context

def test_enrich_returns_new_finding_instance():
    f = _finding()
    pr = PRContext(pr_body="", commit_messages=())
    enriched = enrich(f, "no docstring here\n", pr)
    assert enriched is not f

def test_enrich_does_not_mutate_original():
    f = _finding()
    pr = PRContext(pr_body="", commit_messages=())
    enrich(f, "code\n", pr)
    assert f.doc_context == ""

def test_evidence_confidence_base_score_from_sarif():
    f = _finding()
    score = evidence_confidence(f, None)
    assert score == pytest.approx(0.4)

def test_evidence_confidence_adds_doc_context_bonus():
    f = _finding(doc_context="important comment")
    score = evidence_confidence(f, None)
    assert score == pytest.approx(0.7)

def test_evidence_confidence_adds_pr_body_reference():
    f = _finding(file="main.tf", doc_context="")
    pr = PRContext(pr_body="changes in main.tf to fix encryption", commit_messages=())
    score = evidence_confidence(f, pr)
    assert score == pytest.approx(0.7)

def test_evidence_confidence_adds_commit_message_reference():
    f = _finding(file="main.tf", doc_context="")
    pr = PRContext(pr_body="", commit_messages=("fix: update main.tf encryption",))
    score = evidence_confidence(f, pr)
    assert score == pytest.approx(0.7)

def test_evidence_confidence_caps_at_1_0():
    f = _finding(file="main.tf", doc_context="important doc")
    pr = PRContext(pr_body="changes in main.tf", commit_messages=("update main.tf",))
    score = evidence_confidence(f, pr)
    assert score == pytest.approx(1.0)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_evidence.py -v
```

Expected: FAIL — `audit_packs.evidence` not found.

- [ ] **Step 3: Implement `evidence.py`**

Create `src/audit_packs/evidence.py`:

```python
from __future__ import annotations
import re
from dataclasses import dataclass, replace

import requests

from audit_packs.models import Finding


@dataclass(frozen=True)
class PRContext:
    pr_body: str
    commit_messages: tuple[str, ...]


def fetch_pr_context(repo: str, pr_number: str, token: str) -> PRContext:
    """Fetch PR body and last 5 commit subjects from GitHub API. IO boundary."""
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    base = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"

    pr_resp = requests.get(base, headers=headers, timeout=15)
    pr_resp.raise_for_status()
    pr_body = (pr_resp.json().get("body") or "")[:500]

    commits_resp = requests.get(f"{base}/commits", headers=headers, timeout=15)
    commits_resp.raise_for_status()
    commits = commits_resp.json()[-5:]
    subjects = tuple(c["commit"]["message"].splitlines()[0] for c in commits)

    return PRContext(pr_body=pr_body, commit_messages=subjects)


def extract_doc_context(file_text: str, line: int) -> str:
    """Return the nearest docstring or block comment within ±10 lines of *line*."""
    lines = file_text.splitlines()
    window_start = max(0, line - 11)
    window_end = min(len(lines), line + 10)
    window = lines[window_start:window_end]

    # Python triple-quoted strings
    triple_pattern = re.compile(r'"""(.*?)"""|\'\'\'(.*?)\'\'\'', re.DOTALL)
    window_text = "\n".join(window)
    for m in triple_pattern.finditer(window_text):
        content = (m.group(1) or m.group(2) or "").strip()
        if content:
            return content[:300]

    # HCL / shell / YAML block comments (# prefix)
    comment_pattern = re.compile(r'^\s*#\s*(.+)$')
    for ln in window:
        m = comment_pattern.match(ln)
        if m:
            return m.group(1).strip()

    return ""


def enrich(finding: Finding, changed_file_text: str, pr_context: PRContext) -> Finding:
    """Return a new Finding with doc_context populated. Never mutates the original."""
    doc_ctx = extract_doc_context(changed_file_text, finding.line)
    return replace(finding, doc_context=doc_ctx)


def evidence_confidence(finding: Finding, pr_context: PRContext | None) -> float:
    """
    Compute evidence_confidence [0.0, 1.0].

    +0.4  SARIF code snippet always present
    +0.3  doc_context non-empty
    +0.3  PR body or any commit message references finding.file
    """
    score = 0.4
    if finding.doc_context:
        score += 0.3
    if pr_context:
        file_ref = (
            finding.file in pr_context.pr_body
            or any(finding.file in msg for msg in pr_context.commit_messages)
        )
        if file_ref:
            score += 0.3
    return min(score, 1.0)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_evidence.py -v
```

Expected: All PASS.

- [ ] **Step 5: Run full suite**

```bash
pytest -v
```

Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/audit_packs/evidence.py tests/test_evidence.py
git commit -m "feat: add evidence.py with PRContext, enrich(), extract_doc_context(), evidence_confidence()"
```

---

## Task 4: CodeQL SARIF Ingestion + Normalize Extension

**Files:**
- Modify: `src/audit_packs/engines.py`
- Modify: `src/audit_packs/normalize.py`
- Create: `tests/test_codeql_normalize.py`

**Interfaces:**
- Consumes: `PathNode`, `Finding` from `models.py` (Task 1)
- Produces:
  - `engines.py`: `read_codeql_sarif(sarif_dir: str) -> dict`
  - `normalize.py`: `sarif_to_findings()` extended to populate `evidence_path`; `extract_rule_confidences(sarif: dict) -> dict[str, float]`

- [ ] **Step 1: Write failing tests**

Create `tests/test_codeql_normalize.py`:

```python
import json
import pathlib
import tempfile
import os
from audit_packs.engines import read_codeql_sarif
from audit_packs.normalize import sarif_to_findings, extract_rule_confidences
from audit_packs.models import PathNode

CODEQL_SARIF_WITH_FLOWS = {
    "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": [
            {"id": "python/CWE-312", "properties": {"confidence": "HIGH"}}
        ]}},
        "results": [{
            "ruleId": "python/CWE-312",
            "level": "error",
            "message": {"text": "Cleartext storage of sensitive information"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "app/models.py"},
                "region": {"startLine": 42, "snippet": {"text": "password = plaintext"}}
            }}],
            "codeFlows": [{
                "threadFlows": [{
                    "locations": [
                        {
                            "location": {"physicalLocation": {
                                "artifactLocation": {"uri": "app/views.py"},
                                "region": {"startLine": 14}
                            }, "message": {"text": "source: user-controlled input"}},
                        },
                        {
                            "location": {"physicalLocation": {
                                "artifactLocation": {"uri": "app/models.py"},
                                "region": {"startLine": 42}
                            }, "message": {"text": "reaches sink: cleartext storage"}},
                        },
                    ]
                }]
            }]
        }]
    }]
}

def test_sarif_with_codeflows_produces_evidence_path():
    findings = sarif_to_findings(CODEQL_SARIF_WITH_FLOWS, "codeql")
    assert len(findings) == 1
    f = findings[0]
    assert len(f.evidence_path) == 2
    assert isinstance(f.evidence_path[0], PathNode)
    assert f.evidence_path[0].line == 14
    assert "source" in f.evidence_path[0].description
    assert f.evidence_path[1].line == 42

def test_sarif_without_codeflows_has_empty_evidence_path():
    sarif = {"runs": [{"results": [{
        "ruleId": "CKV_AWS_19",
        "level": "error",
        "message": {"text": "Encryption disabled"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "main.tf"},
            "region": {"startLine": 5}
        }}]
    }]}]}
    findings = sarif_to_findings(sarif, "checkov")
    assert findings[0].evidence_path == ()

def test_extract_rule_confidences_maps_high_to_09():
    confidences = extract_rule_confidences(CODEQL_SARIF_WITH_FLOWS)
    assert confidences.get("python/CWE-312") == pytest.approx(0.9)

def test_extract_rule_confidences_returns_empty_when_no_rules():
    confidences = extract_rule_confidences({"runs": []})
    assert confidences == {}

def test_read_codeql_sarif_merges_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        sarif1 = {"runs": [{"results": [{"ruleId": "A"}]}]}
        sarif2 = {"runs": [{"results": [{"ruleId": "B"}]}]}
        pathlib.Path(tmpdir, "a.sarif").write_text(json.dumps(sarif1))
        pathlib.Path(tmpdir, "b.sarif").write_text(json.dumps(sarif2))
        merged = read_codeql_sarif(tmpdir)
        assert len(merged["runs"]) == 2

def test_read_codeql_sarif_returns_empty_for_missing_dir():
    merged = read_codeql_sarif("/nonexistent/path")
    assert merged == {"runs": []}

def test_read_codeql_sarif_returns_empty_for_empty_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        merged = read_codeql_sarif(tmpdir)
        assert merged == {"runs": []}

import pytest
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_codeql_normalize.py -v
```

Expected: FAIL — `read_codeql_sarif` and `extract_rule_confidences` not found.

- [ ] **Step 3: Add `read_codeql_sarif()` to `engines.py`**

Append to `src/audit_packs/engines.py`:

```python
def read_codeql_sarif(sarif_dir: str) -> dict:
    """Merge all .sarif files in sarif_dir into a single SARIF dict. IO boundary."""
    import glob
    if not os.path.isdir(sarif_dir):
        return {"runs": []}
    runs = []
    for path in glob.glob(os.path.join(sarif_dir, "*.sarif")):
        try:
            with open(path) as fh:
                data = json.load(fh)
            runs.extend(data.get("runs", []))
        except (json.JSONDecodeError, OSError):
            pass
    return {"runs": runs}
```

- [ ] **Step 4: Extend `normalize.py` with codeFlows extraction and `extract_rule_confidences()`**

Replace `src/audit_packs/normalize.py` with:

```python
from audit_packs.models import Finding, PathNode

_LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "low"}
_PROP_TO_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "low"}
_CONFIDENCE_MAP = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}


def _extract_evidence_path(result: dict) -> tuple[PathNode, ...]:
    """Parse codeFlows[0].threadFlows[0].locations into PathNode tuples."""
    code_flows = result.get("codeFlows", [])
    if not code_flows:
        return ()
    thread_flows = code_flows[0].get("threadFlows", [])
    if not thread_flows:
        return ()
    locations = thread_flows[0].get("locations", [])
    nodes = []
    for loc_entry in locations:
        loc = loc_entry.get("location", {})
        phys = loc.get("physicalLocation", {})
        uri = phys.get("artifactLocation", {}).get("uri", "")
        line = phys.get("region", {}).get("startLine", 0)
        snippet = phys.get("region", {}).get("snippet", {}).get("text", "")
        description = loc.get("message", {}).get("text", "")
        nodes.append(PathNode(file=uri, line=int(line), snippet=snippet, description=description))
    return tuple(nodes)


def sarif_to_findings(sarif: dict, engine: str) -> list[Finding]:
    findings: list[Finding] = []
    for run in sarif.get("runs", []):
        for res in run.get("results", []):
            locs = res.get("locations", [])
            if not locs:
                continue
            phys = locs[0].get("physicalLocation", {})
            path = phys.get("artifactLocation", {}).get("uri", "")
            line = phys.get("region", {}).get("startLine", 1)
            msg = res.get("message", {}).get("text", "")
            snippet = phys.get("region", {}).get("snippet", {}).get("text", "")
            prop_sev = _PROP_TO_SEVERITY.get(res.get("properties", {}).get("severity", "").upper())
            level_sev = _LEVEL_TO_SEVERITY.get(res.get("level", "warning"), "medium")
            evidence_path = _extract_evidence_path(res)
            findings.append(Finding(
                check_id=res.get("ruleId", ""),
                engine=engine,
                file=path,
                line=int(line),
                severity=prop_sev or level_sev,
                message=msg,
                evidence=snippet or msg,
                evidence_path=evidence_path,
            ))
    return findings


def extract_rule_confidences(sarif: dict) -> dict[str, float]:
    """Return {rule_id → confidence_score} from SARIF tool rule metadata."""
    confidences: dict[str, float] = {}
    for run in sarif.get("runs", []):
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        for rule in rules:
            rule_id = rule.get("id", "")
            conf_str = rule.get("properties", {}).get("confidence", "")
            if conf_str.upper() in _CONFIDENCE_MAP:
                confidences[rule_id] = _CONFIDENCE_MAP[conf_str.upper()]
    return confidences
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_codeql_normalize.py tests/test_normalize.py -v
```

Expected: All PASS (including existing normalize tests).

- [ ] **Step 6: Run full suite**

```bash
pytest -v
```

Expected: All PASS.

- [ ] **Step 7: Commit**

```bash
git add src/audit_packs/engines.py src/audit_packs/normalize.py tests/test_codeql_normalize.py
git commit -m "feat: add read_codeql_sarif() to engines, extend normalize with codeFlows→PathNode and extract_rule_confidences()"
```

---

## Task 5: Confidence Module

**Files:**
- Create: `src/audit_packs/confidence.py`
- Create: `tests/test_confidence.py`

**Interfaces:**
- Consumes: `AdjudicationResult`, `AdjudicationMode` from `models.py` (Task 1)
- Produces:
  - `ScoreComponents(rule_confidence, evidence_confidence, model_consensus, historical_precision, control_severity, flow_confidence)`
  - `ScoredFinding(result, components, finding_score, surfaced, suppression_reason)`
  - `score_finding(result, components, weights) -> float`
  - `apply_confidence_gate(pairs, threshold, mode, weights) -> list[ScoredFinding]`
  - `get_historical_precision(check_id, framework, data) -> float`
  - `update_precision(check_id, framework, data) -> dict`
  - `DEFAULT_WEIGHTS: dict[str, float]`

- [ ] **Step 1: Write failing tests**

Create `tests/test_confidence.py`:

```python
import pytest
from audit_packs.models import (
    Finding, ControlFinding, AdjudicationResult, AdjudicationMode
)
from audit_packs.confidence import (
    ScoreComponents, ScoredFinding, score_finding, apply_confidence_gate,
    get_historical_precision, update_precision, DEFAULT_WEIGHTS
)

def _result(judge_score=0.8):
    f = Finding("CKV_AWS_19", "checkov", "main.tf", 5, "high", "msg", "snippet")
    cf = ControlFinding(f, "gdpr", "SC-28", "Protection at Rest")
    return AdjudicationResult(
        control_finding=cf,
        detector_score=judge_score,
        verifier_argument="real violation",
        adversarial_argument="test infra",
        judge_score=judge_score,
        model_consensus=judge_score,
        rationale="Evidence is clear.",
    )

def _components(**overrides):
    defaults = dict(
        rule_confidence=0.9, evidence_confidence=0.7, model_consensus=0.8,
        historical_precision=0.8, control_severity=0.8, flow_confidence=0.5
    )
    defaults.update(overrides)
    return ScoreComponents(**defaults)

def test_default_weights_sum_to_1():
    assert abs(sum(DEFAULT_WEIGHTS.values()) - 1.0) < 0.001

def test_score_finding_weighted_sum():
    result = _result(judge_score=0.8)
    comps = _components(
        rule_confidence=1.0, evidence_confidence=1.0, model_consensus=1.0,
        historical_precision=1.0, control_severity=1.0, flow_confidence=1.0
    )
    score = score_finding(result, comps, DEFAULT_WEIGHTS)
    assert score == pytest.approx(1.0)

def test_score_finding_zero_when_all_zeros():
    result = _result(judge_score=0.0)
    comps = _components(
        rule_confidence=0.0, evidence_confidence=0.0, model_consensus=0.0,
        historical_precision=0.0, control_severity=0.0, flow_confidence=0.0
    )
    score = score_finding(result, comps, DEFAULT_WEIGHTS)
    assert score == pytest.approx(0.0)

def test_apply_gate_enforce_suppresses_below_threshold():
    result = _result(judge_score=0.4)
    comps = _components(model_consensus=0.4, rule_confidence=0.3, evidence_confidence=0.4,
                         historical_precision=0.4, control_severity=0.4, flow_confidence=0.4)
    pairs = [(result, comps)]
    scored = apply_confidence_gate(pairs, threshold=0.70, mode=AdjudicationMode.ENFORCE, weights=DEFAULT_WEIGHTS)
    assert len(scored) == 1
    assert scored[0].surfaced is False
    assert "0.70" in scored[0].suppression_reason

def test_apply_gate_enforce_surfaces_above_threshold():
    result = _result(judge_score=0.9)
    comps = _components()
    pairs = [(result, comps)]
    scored = apply_confidence_gate(pairs, threshold=0.70, mode=AdjudicationMode.ENFORCE, weights=DEFAULT_WEIGHTS)
    assert scored[0].surfaced is True
    assert scored[0].suppression_reason == ""

def test_apply_gate_advisory_surfaces_all():
    result = _result(judge_score=0.1)
    comps = _components(model_consensus=0.1, rule_confidence=0.1, evidence_confidence=0.1,
                         historical_precision=0.1, control_severity=0.1, flow_confidence=0.1)
    pairs = [(result, comps)]
    scored = apply_confidence_gate(pairs, threshold=0.70, mode=AdjudicationMode.ADVISORY, weights=DEFAULT_WEIGHTS)
    assert scored[0].surfaced is True

def test_apply_gate_off_surfaces_all_regardless_of_score():
    result = _result(judge_score=0.0)
    comps = _components(model_consensus=0.0, rule_confidence=0.0, evidence_confidence=0.0,
                         historical_precision=0.0, control_severity=0.0, flow_confidence=0.0)
    pairs = [(result, comps)]
    scored = apply_confidence_gate(pairs, threshold=0.70, mode=AdjudicationMode.OFF, weights=DEFAULT_WEIGHTS)
    assert scored[0].surfaced is True

def test_get_historical_precision_default_prior():
    score = get_historical_precision("UNKNOWN_CHECK", "gdpr", {})
    assert score == pytest.approx(4 / 5)

def test_get_historical_precision_from_data():
    data = {"CKV_AWS_19:gdpr": {"alpha": 7, "beta": 3}}
    score = get_historical_precision("CKV_AWS_19", "gdpr", data)
    assert score == pytest.approx(0.7)

def test_update_precision_creates_entry_if_missing():
    data = {}
    updated = update_precision("CKV_AWS_19", "gdpr", data)
    assert updated["CKV_AWS_19:gdpr"]["alpha"] == 5
    assert updated["CKV_AWS_19:gdpr"]["beta"] == 1

def test_update_precision_increments_alpha():
    data = {"CKV_AWS_19:gdpr": {"alpha": 5, "beta": 1}}
    updated = update_precision("CKV_AWS_19", "gdpr", data)
    assert updated["CKV_AWS_19:gdpr"]["alpha"] == 6
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_confidence.py -v
```

Expected: FAIL — `audit_packs.confidence` not found.

- [ ] **Step 3: Implement `confidence.py`**

Create `src/audit_packs/confidence.py`:

```python
from __future__ import annotations
from dataclasses import dataclass
from audit_packs.models import AdjudicationResult, AdjudicationMode

DEFAULT_WEIGHTS: dict[str, float] = {
    "rule": 0.20,
    "evidence": 0.15,
    "consensus": 0.25,
    "history": 0.10,
    "severity": 0.10,
    "flow": 0.20,
}

_SEVERITY_MAP = {"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4}


@dataclass(frozen=True)
class ScoreComponents:
    rule_confidence: float
    evidence_confidence: float
    model_consensus: float
    historical_precision: float
    control_severity: float
    flow_confidence: float


@dataclass(frozen=True)
class ScoredFinding:
    result: AdjudicationResult
    components: ScoreComponents
    finding_score: float
    surfaced: bool
    suppression_reason: str


def score_finding(
    result: AdjudicationResult,
    components: ScoreComponents,
    weights: dict[str, float],
) -> float:
    return (
        weights["rule"] * components.rule_confidence
        + weights["evidence"] * components.evidence_confidence
        + weights["consensus"] * components.model_consensus
        + weights["history"] * components.historical_precision
        + weights["severity"] * components.control_severity
        + weights["flow"] * components.flow_confidence
    )


def apply_confidence_gate(
    pairs: list[tuple[AdjudicationResult, ScoreComponents]],
    threshold: float,
    mode: AdjudicationMode,
    weights: dict[str, float],
) -> list[ScoredFinding]:
    results = []
    for result, components in pairs:
        fs = score_finding(result, components, weights)
        if mode in (AdjudicationMode.OFF, AdjudicationMode.ADVISORY):
            surfaced = True
            reason = ""
        else:  # ENFORCE
            surfaced = fs >= threshold
            reason = "" if surfaced else f"score {fs:.2f} < threshold {threshold:.2f}"
        results.append(ScoredFinding(
            result=result,
            components=components,
            finding_score=fs,
            surfaced=surfaced,
            suppression_reason=reason,
        ))
    return results


def get_historical_precision(check_id: str, framework: str, data: dict) -> float:
    """Posterior mean of Beta(alpha, beta). Default prior: alpha=4, beta=1 → 0.8."""
    key = f"{check_id}:{framework}"
    if key not in data:
        return 4 / 5
    entry = data[key]
    return entry["alpha"] / (entry["alpha"] + entry["beta"])


def update_precision(check_id: str, framework: str, data: dict) -> dict:
    """Confirm a TP: increment alpha. Creates entry with alpha=5, beta=1 if absent."""
    key = f"{check_id}:{framework}"
    if key not in data:
        data[key] = {"alpha": 5, "beta": 1}
    else:
        data[key]["alpha"] += 1
    return data


def control_severity_score(severity: str) -> float:
    return _SEVERITY_MAP.get(severity, 0.6)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_confidence.py -v
```

Expected: All PASS.

- [ ] **Step 5: Run full suite**

```bash
pytest -v
```

Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/audit_packs/confidence.py tests/test_confidence.py
git commit -m "feat: add confidence.py with composite scoring formula, gate logic, and precision history"
```

---

## Task 6: Detection Agents Stub

**Files:**
- Create: `src/audit_packs/agents.py`
- Create: `tests/test_agents.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `DetectionAgent` ABC with `detect(changed_files: dict[str, str]) -> dict`
  - `NoOpAgent(framework="noop")` — always returns `{"runs": []}`

- [ ] **Step 1: Write failing tests**

Create `tests/test_agents.py`:

```python
from audit_packs.agents import DetectionAgent, NoOpAgent

def test_noop_agent_returns_empty_sarif():
    agent = NoOpAgent()
    result = agent.detect({"main.tf": "resource..."})
    assert result == {"runs": []}

def test_noop_agent_framework_is_noop():
    assert NoOpAgent.framework == "noop"

def test_noop_agent_is_detection_agent():
    assert isinstance(NoOpAgent(), DetectionAgent)

def test_noop_agent_accepts_empty_changed_files():
    agent = NoOpAgent()
    assert agent.detect({}) == {"runs": []}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_agents.py -v
```

Expected: FAIL — `audit_packs.agents` not found.

- [ ] **Step 3: Implement `agents.py`**

Create `src/audit_packs/agents.py`:

```python
from __future__ import annotations
from abc import ABC, abstractmethod


class DetectionAgent(ABC):
    framework: str

    @abstractmethod
    def detect(self, changed_files: dict[str, str]) -> dict:
        """Return a SARIF dict. engine tag: f'{self.framework}-agent'."""


class NoOpAgent(DetectionAgent):
    framework = "noop"

    def detect(self, changed_files: dict[str, str]) -> dict:
        return {"runs": []}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_agents.py -v
```

Expected: All PASS.

- [ ] **Step 5: Run full suite**

```bash
pytest -v
```

Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/audit_packs/agents.py tests/test_agents.py
git commit -m "feat: add agents.py with DetectionAgent ABC and NoOpAgent stub"
```

---

## Task 7: Adjudicate Rewrite + Model Config

**Files:**
- Rewrite: `src/audit_packs/adjudicate.py`
- Create: `audit-models.yaml`
- Rewrite: `tests/test_adjudicate.py`

**Interfaces:**
- Consumes: `ControlFinding`, `AdjudicationResult`, `AdjudicationMode` from `models.py` (Task 1); `PRContext` from `evidence.py` (Task 3)
- Produces:
  - `load_model_config(config_path: str) -> dict`
  - `adjudicate(cf: ControlFinding, pr_context: PRContext | None, mode: AdjudicationMode, model_config: dict) -> AdjudicationResult`
  - Re-exports `AdjudicationMode` from `models` (backward compat)

- [ ] **Step 1: Write failing tests**

Replace `tests/test_adjudicate.py` with:

```python
"""Tests for the rewritten 4-role adjudicate.py."""
import os
import json
import tempfile
import pytest
from unittest.mock import MagicMock, patch, call
from audit_packs.models import Finding, ControlFinding, AdjudicationMode, AdjudicationResult
from audit_packs.evidence import PRContext
from audit_packs.adjudicate import adjudicate, load_model_config, AdjudicationMode  # noqa

def _cf():
    f = Finding("CKV_AWS_19", "checkov", "main.tf", 5, "high", "S3 not encrypted", "encrypted=false")
    return ControlFinding(f, "gdpr", "SC-28", "Protection of Information at Rest")

def _pr():
    return PRContext(pr_body="Fix S3 encryption", commit_messages=("fix: enable S3 encryption",))

_DEFAULT_CONFIG = {
    "detector": {"provider": "openai", "model": "gpt-4o", "base_url": None, "api_key_env": "OPENAI_API_KEY"},
    "verifier": {"provider": "anthropic", "model": "claude-opus-4-5", "base_url": None, "api_key_env": "ANTHROPIC_API_KEY"},
    "adversarial": {"provider": "google", "model": "gemini-1.5-pro", "base_url": None, "api_key_env": "GOOGLE_API_KEY"},
    "judge": {"provider": "openai", "model": "gpt-4o", "base_url": None, "api_key_env": "OPENAI_API_KEY"},
}

class TestAdjudicateModeOff:
    def test_returns_neutral_result_when_mode_off(self):
        result = adjudicate(_cf(), None, AdjudicationMode.OFF, _DEFAULT_CONFIG)
        assert isinstance(result, AdjudicationResult)
        assert result.model_consensus == 1.0

    def test_mode_off_does_not_call_any_llm(self):
        with patch("audit_packs.adjudicate._call_role") as mock:
            adjudicate(_cf(), None, AdjudicationMode.OFF, _DEFAULT_CONFIG)
            mock.assert_not_called()

class TestAdjudicatePipeline:
    def _mock_call_role(self, role_responses: dict):
        """Returns a mock that returns different JSON per system_prompt substring."""
        responses_list = []
        for key in ["detector", "verifier", "adversarial", "judge"]:
            if key in role_responses:
                responses_list.append(role_responses[key])

        call_count = [0]
        def side_effect(role_cfg, system_prompt, user_content):
            idx = call_count[0]
            call_count[0] += 1
            return responses_list[idx % len(responses_list)]

        return side_effect

    def test_sequential_pipeline_calls_four_roles(self, monkeypatch):
        calls = []
        def mock_call(role_cfg, system_prompt, user_content):
            if "compliance expert" in system_prompt:
                calls.append("detector")
                return {"confidence": 0.8, "assessment": "Likely violation"}
            elif "prosecution" in system_prompt or "IS a genuine violation" in system_prompt:
                calls.append("verifier")
                return {"argument": "data stored plaintext", "strength": 0.9}
            elif "defence" in system_prompt or "FALSE POSITIVE" in system_prompt:
                calls.append("adversarial")
                return {"argument": "this is a test bucket", "strength": 0.3}
            elif "judge" in system_prompt:
                calls.append("judge")
                return {"confidence": 0.75, "rationale": "Evidence supports violation"}
            return {"confidence": 0.5, "rationale": "fallback"}

        with patch("audit_packs.adjudicate._call_role", side_effect=mock_call):
            result = adjudicate(_cf(), _pr(), AdjudicationMode.ENFORCE, _DEFAULT_CONFIG)

        assert "detector" in calls
        assert "verifier" in calls
        assert "adversarial" in calls
        assert "judge" in calls
        assert result.judge_score == pytest.approx(0.75)
        assert result.model_consensus == result.judge_score

    def test_detector_failure_returns_neutral(self, monkeypatch):
        with patch("audit_packs.adjudicate._call_role", side_effect=Exception("API down")):
            result = adjudicate(_cf(), _pr(), AdjudicationMode.ENFORCE, _DEFAULT_CONFIG)
        assert result.model_consensus == 0.5

    def test_judge_failure_falls_back_to_detector_score(self, monkeypatch):
        call_count = [0]
        def mock_call(role_cfg, system_prompt, user_content):
            call_count[0] += 1
            if call_count[0] == 1:
                return {"confidence": 0.82, "assessment": "Violation found"}
            if call_count[0] in (2, 3):
                return {"argument": "arg", "strength": 0.5}
            raise Exception("Judge down")

        with patch("audit_packs.adjudicate._call_role", side_effect=mock_call):
            result = adjudicate(_cf(), _pr(), AdjudicationMode.ENFORCE, _DEFAULT_CONFIG)
        assert result.model_consensus == pytest.approx(0.82)

class TestLoadModelConfig:
    def test_returns_defaults_when_file_missing(self, tmp_path):
        cfg = load_model_config(str(tmp_path / "nonexistent.yaml"))
        assert cfg["detector"]["model"] == "gpt-4o"
        assert cfg["verifier"]["provider"] == "anthropic"

    def test_yaml_file_overrides_role(self, tmp_path):
        config_path = tmp_path / "audit-models.yaml"
        config_path.write_text(
            "models:\n  detector:\n    provider: openai\n    model: gpt-5\n"
        )
        cfg = load_model_config(str(config_path))
        assert cfg["detector"]["model"] == "gpt-5"
        assert cfg["verifier"]["provider"] == "anthropic"

    def test_invalid_yaml_raises_value_error(self, tmp_path):
        config_path = tmp_path / "bad.yaml"
        config_path.write_text("models: [\n  invalid: yaml: [\n")
        with pytest.raises(ValueError, match="Invalid YAML"):
            load_model_config(str(config_path))

    def test_unknown_provider_raises_value_error(self, tmp_path):
        config_path = tmp_path / "audit-models.yaml"
        config_path.write_text(
            "models:\n  detector:\n    provider: unknown_llm\n    model: x\n"
        )
        with pytest.raises(ValueError, match="unsupported provider"):
            load_model_config(str(config_path))

    def test_env_var_overrides_yaml(self, tmp_path, monkeypatch):
        config_path = tmp_path / "audit-models.yaml"
        config_path.write_text("models:\n  detector:\n    model: gpt-4o\n")
        monkeypatch.setenv("DETECTOR_MODEL", "gpt-5-turbo")
        cfg = load_model_config(str(config_path))
        assert cfg["detector"]["model"] == "gpt-5-turbo"

class TestCaching:
    def test_cache_hit_skips_llm_calls(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AUDIT_CACHE", "on")
        cache_dir = tmp_path / ".audit-cache"
        cache_dir.mkdir()

        cached = {
            "detector_score": 0.9, "verifier_argument": "v",
            "adversarial_argument": "a", "judge_score": 0.9,
            "model_consensus": 0.9, "rationale": "cached",
        }
        cf = _cf()
        import hashlib
        key = hashlib.sha256(
            f"{cf.finding.check_id}|{cf.framework}|{cf.finding.file}|{cf.control_id}".encode()
        ).hexdigest()
        (cache_dir / f"{key}.json").write_text(json.dumps(cached))

        with patch("audit_packs.adjudicate._CACHE_DIR", str(cache_dir)):
            with patch("audit_packs.adjudicate._call_role") as mock:
                result = adjudicate(cf, _pr(), AdjudicationMode.ENFORCE, _DEFAULT_CONFIG)
                mock.assert_not_called()
        assert result.model_consensus == pytest.approx(0.9)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_adjudicate.py -v
```

Expected: Some PASS (the import of AdjudicationMode still works), most FAIL due to interface mismatch.

- [ ] **Step 3: Create `audit-models.yaml`**

Create `audit-models.yaml` at the repo root:

```yaml
# Default model routing for audit-packs.
# Supports providers: openai, anthropic, google, ollama, openai-compatible
# Override any role with env vars: DETECTOR_MODEL, VERIFIER_MODEL, etc.
models:
  detector:
    provider: openai
    model: gpt-4o
    base_url: null
    api_key_env: OPENAI_API_KEY

  verifier:
    provider: anthropic
    model: claude-opus-4-5
    base_url: null
    api_key_env: ANTHROPIC_API_KEY

  adversarial:
    provider: google
    model: gemini-1.5-pro
    base_url: null
    api_key_env: GOOGLE_API_KEY

  judge:
    provider: openai
    model: gpt-4o
    base_url: null
    api_key_env: OPENAI_API_KEY
```

- [ ] **Step 4: Rewrite `adjudicate.py`**

Replace `src/audit_packs/adjudicate.py` with:

```python
"""AI ensemble adjudication for compliance findings.

IO boundary: makes HTTP calls to LLM provider APIs.
Pipeline: Detector → (Verifier ‖ Adversarial) → Judge (sequential with parallel Round 2).
Returns AdjudicationResult with float confidence scores.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml

from audit_packs.models import AdjudicationMode, AdjudicationResult, ControlFinding  # noqa: F401
from audit_packs.evidence import PRContext

log = logging.getLogger(__name__)

_CACHE_DIR = ".audit-cache"

_VALID_PROVIDERS = {"openai", "anthropic", "google", "ollama", "openai-compatible"}

_ROLE_DEFAULTS: dict[str, dict] = {
    "detector": {"provider": "openai", "model": "gpt-4o", "base_url": None, "api_key_env": "OPENAI_API_KEY"},
    "verifier": {"provider": "anthropic", "model": "claude-opus-4-5", "base_url": None, "api_key_env": "ANTHROPIC_API_KEY"},
    "adversarial": {"provider": "google", "model": "gemini-1.5-pro", "base_url": None, "api_key_env": "GOOGLE_API_KEY"},
    "judge": {"provider": "openai", "model": "gpt-4o", "base_url": None, "api_key_env": "OPENAI_API_KEY"},
}


# ---------------------------------------------------------------------------
# Model config loading
# ---------------------------------------------------------------------------

def load_model_config(config_path: str = "audit-models.yaml") -> dict:
    """Load model routing config; apply env var overrides. Returns per-role config dict."""
    config = {role: dict(defaults) for role, defaults in _ROLE_DEFAULTS.items()}

    if os.path.exists(config_path):
        try:
            with open(config_path) as fh:
                raw = yaml.safe_load(fh) or {}
        except Exception as exc:
            raise ValueError(f"Invalid YAML in {config_path!r}: {exc}") from exc

        for role in _ROLE_DEFAULTS:
            role_cfg = raw.get("models", {}).get(role, {})
            for key in ("provider", "model", "base_url", "api_key_env"):
                if key in role_cfg:
                    config[role][key] = role_cfg[key]

        for role in _ROLE_DEFAULTS:
            provider = config[role]["provider"]
            if provider not in _VALID_PROVIDERS:
                raise ValueError(f"Role {role!r}: unsupported provider {provider!r}")

    for role in _ROLE_DEFAULTS:
        env_prefix = role.upper()
        for key, env_suffix in [("model", "MODEL"), ("provider", "PROVIDER"), ("base_url", "BASE_URL")]:
            val = os.environ.get(f"{env_prefix}_{env_suffix}", "")
            if val:
                config[role][key] = val

    return config


# ---------------------------------------------------------------------------
# Provider dispatch
# ---------------------------------------------------------------------------

def _call_role(role_cfg: dict, system_prompt: str, user_content: str) -> dict:
    """Call one LLM role and return parsed JSON dict."""
    provider = role_cfg["provider"]
    model = role_cfg["model"]
    api_key_env = role_cfg.get("api_key_env") or ""
    base_url = role_cfg.get("base_url") or None
    api_key = os.environ.get(api_key_env, "") if api_key_env else ""

    if provider in ("openai", "openai-compatible"):
        import openai
        client = openai.OpenAI(api_key=api_key or "dummy", base_url=base_url)
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            response_format={"type": "json_object"},
            max_tokens=512,
        )
        return json.loads(resp.choices[0].message.content)

    if provider == "ollama":
        import openai
        client = openai.OpenAI(api_key="ollama", base_url=base_url or "http://localhost:11434/v1")
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            max_tokens=512,
        )
        return json.loads(resp.choices[0].message.content)

    if provider == "anthropic":
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        resp = client.messages.create(
            model=model,
            max_tokens=512,
            system=system_prompt,
            messages=[{"role": "user", "content": user_content}],
        )
        return json.loads(resp.content[0].text)

    if provider == "google":
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        gm = genai.GenerativeModel(model, system_instruction=system_prompt)
        resp = gm.generate_content(user_content)
        return json.loads(resp.text)

    raise ValueError(f"Unknown provider: {provider!r}")


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _cache_key(cf: ControlFinding) -> str:
    raw = f"{cf.finding.check_id}|{cf.framework}|{cf.finding.file}|{cf.control_id}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _load_cache(cf: ControlFinding) -> AdjudicationResult | None:
    if os.environ.get("AUDIT_CACHE", "on") == "off":
        return None
    path = os.path.join(_CACHE_DIR, f"{_cache_key(cf)}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path) as fh:
            data = json.load(fh)
        return AdjudicationResult(
            control_finding=cf,
            detector_score=data["detector_score"],
            verifier_argument=data["verifier_argument"],
            adversarial_argument=data["adversarial_argument"],
            judge_score=data["judge_score"],
            model_consensus=data["model_consensus"],
            rationale=data["rationale"],
        )
    except Exception:
        return None


def _save_cache(cf: ControlFinding, result: AdjudicationResult) -> None:
    if os.environ.get("AUDIT_CACHE", "on") == "off":
        return
    os.makedirs(_CACHE_DIR, exist_ok=True)
    path = os.path.join(_CACHE_DIR, f"{_cache_key(cf)}.json")
    try:
        with open(path, "w") as fh:
            json.dump({
                "detector_score": result.detector_score,
                "verifier_argument": result.verifier_argument,
                "adversarial_argument": result.adversarial_argument,
                "judge_score": result.judge_score,
                "model_consensus": result.model_consensus,
                "rationale": result.rationale,
            }, fh)
    except Exception as exc:
        log.debug("adjudicate: cache write failed: %s", exc)


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------

def _finding_context(cf: ControlFinding, pr_context: PRContext | None) -> str:
    f = cf.finding
    path_text = ""
    if f.evidence_path:
        path_text = "\nEvidence path:\n" + "\n".join(
            f"  {i+1}. [{node.file}:{node.line}] {node.snippet}  ← {node.description}"
            for i, node in enumerate(f.evidence_path)
        )
    flow_text = ""
    if f.doc_context:
        flow_text = f"\nDoc comment: {f.doc_context}"
    pr_text = ""
    if pr_context:
        pr_text = (
            f"\nPR context: {pr_context.pr_body}"
            + (f"\nRecent commits: {'; '.join(pr_context.commit_messages)}" if pr_context.commit_messages else "")
        )
    return (
        f"Control: {cf.control_id} — {cf.control_title}\n"
        f"Framework: {cf.framework}\n"
        f"Finding: {f.check_id} on {f.file}:{f.line} ({f.engine})\n"
        f"Severity: {f.severity}\n"
        f"Message: {f.message}\n"
        f"Evidence: {f.evidence}"
        + path_text + flow_text + pr_text
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def adjudicate(
    cf: ControlFinding,
    pr_context: PRContext | None,
    mode: AdjudicationMode,
    model_config: dict,
) -> AdjudicationResult:
    """Run the 4-role ensemble for one ControlFinding. Returns AdjudicationResult."""
    if mode is AdjudicationMode.OFF:
        return AdjudicationResult(
            control_finding=cf,
            detector_score=1.0,
            verifier_argument="",
            adversarial_argument="",
            judge_score=1.0,
            model_consensus=1.0,
            rationale="adjudication disabled",
        )

    cached = _load_cache(cf)
    if cached is not None:
        return cached

    ctx = _finding_context(cf, pr_context)

    # --- Round 1: Detector ---
    detector_score = 0.5
    detector_assessment = "no assessment"
    try:
        det = _call_role(
            model_config["detector"],
            f"You are a {cf.framework} compliance expert. Assess this finding. "
            "Return JSON: {\"confidence\": <0.0-1.0>, \"assessment\": \"<2-3 sentences>\"}",
            ctx,
        )
        detector_score = float(det.get("confidence", 0.5))
        detector_assessment = det.get("assessment", "")
    except Exception as exc:
        log.warning("adjudicate: detector failed (%s); using neutral score", exc)
        result = AdjudicationResult(
            control_finding=cf,
            detector_score=0.5,
            verifier_argument="",
            adversarial_argument="",
            judge_score=0.5,
            model_consensus=0.5,
            rationale="model_confidence_unavailable",
        )
        return result

    round2_ctx = ctx + f"\n\nDetector assessment (score {detector_score:.2f}): {detector_assessment}"

    # --- Round 2: Verifier + Adversarial (parallel) ---
    verifier_arg = ""
    adversarial_arg = ""

    def _run_verifier():
        return _call_role(
            model_config["verifier"],
            f"You are a strict {cf.framework} compliance auditor. Argue why the following finding "
            "IS a genuine violation. Return JSON: {\"argument\": \"<arg>\", \"strength\": <0.0-1.0>}",
            round2_ctx,
        )

    def _run_adversarial():
        return _call_role(
            model_config["adversarial"],
            "You are defence counsel. Argue why this finding is a FALSE POSITIVE. "
            "Return JSON: {\"argument\": \"<arg>\", \"strength\": <0.0-1.0>}",
            round2_ctx,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        fut_v = executor.submit(_run_verifier)
        fut_a = executor.submit(_run_adversarial)
        try:
            verifier_arg = fut_v.result().get("argument", "")
        except Exception as exc:
            log.warning("adjudicate: verifier failed (%s)", exc)
        try:
            adversarial_arg = fut_a.result().get("argument", "")
        except Exception as exc:
            log.warning("adjudicate: adversarial failed (%s)", exc)

    # --- Round 3: Judge ---
    judge_score = detector_score
    rationale = "judge fallback: using detector score"
    try:
        judge_ctx = (
            f"Detector score: {detector_score:.2f}\n"
            f"Prosecution (verifier): {verifier_arg or '(unavailable)'}\n"
            f"Defence (adversarial): {adversarial_arg or '(unavailable)'}\n\n"
            + ctx
        )
        jud = _call_role(
            model_config["judge"],
            f"You are a senior {cf.framework} compliance judge. Weigh the evidence and return "
            "a final confidence score. Return JSON: {\"confidence\": <0.0-1.0>, \"rationale\": \"<one sentence>\"}",
            judge_ctx,
        )
        judge_score = float(jud.get("confidence", detector_score))
        rationale = jud.get("rationale", "")
    except Exception as exc:
        log.warning("adjudicate: judge failed (%s); using detector score", exc)

    result = AdjudicationResult(
        control_finding=cf,
        detector_score=detector_score,
        verifier_argument=verifier_arg,
        adversarial_argument=adversarial_arg,
        judge_score=judge_score,
        model_consensus=judge_score,
        rationale=rationale,
    )
    _save_cache(cf, result)
    return result
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_adjudicate.py -v
```

Expected: All PASS.

- [ ] **Step 6: Run full suite**

```bash
pytest -v
```

Expected: All PASS.

- [ ] **Step 7: Commit**

```bash
git add src/audit_packs/adjudicate.py audit-models.yaml tests/test_adjudicate.py
git commit -m "feat: rewrite adjudicate.py as 4-role sequential ensemble returning AdjudicationResult; add audit-models.yaml"
```

---

## Task 8: New Semgrep Rules

**Files:**
- Create: `rules/pii-fields.yaml`
- Create: `rules/insecure-config.yaml`

**Interfaces:**
- Produces: Semgrep YAML rules emitting findings tagged `engine: "semgrep"` via the existing normalize pipeline.
- No code changes — rules are data consumed by `run_semgrep()` in `engines.py`.

- [ ] **Step 1: Create `rules/pii-fields.yaml`**

```yaml
rules:
  - id: pii-variable-name
    patterns:
      - pattern-either:
          - pattern: $X = ...
          - pattern: $X = $FUNC(...)
    metavariable-regex:
      metavariable: $X
      regex: '(?i)(ssn|dob|card_number|passport_no|social_security|date_of_birth|credit_card|cvv|tax_id)'
    message: >
      Variable '$X' matches a PII field name pattern. Ensure this data is
      encrypted at rest (GDPR Art. 32-a, HIPAA §164.312(a)(2)(iv), NIST SC-28).
    languages: [python]
    severity: WARNING
    metadata:
      confidence: MEDIUM
      category: security
      cwe: CWE-312
      compliance:
        - GDPR Art-32-a
        - HIPAA §164.312
        - NIST SC-28
```

- [ ] **Step 2: Create `rules/insecure-config.yaml`**

```yaml
rules:
  - id: ssl-verify-disabled
    patterns:
      - pattern-either:
          - pattern: requests.$FUNC(..., verify=False, ...)
          - pattern: requests.$FUNC(..., verify=False)
    message: >
      TLS certificate verification is disabled (verify=False). This allows
      man-in-the-middle attacks (NIST SC-8, GDPR Art-32-b).
    languages: [python]
    severity: ERROR
    metadata:
      confidence: HIGH
      category: security
      cwe: CWE-295
      compliance:
        - NIST SC-8
        - GDPR Art-32-b

  - id: tls-enabled-false
    pattern: tls_enabled = False
    message: >
      TLS is explicitly disabled. All data in transit must be encrypted
      (NIST SC-8, PCI-DSS Req-4).
    languages: [python, generic]
    severity: ERROR
    metadata:
      confidence: HIGH
      category: security
      cwe: CWE-319
      compliance:
        - NIST SC-8
        - PCI-DSS Req-4
```

- [ ] **Step 3: Verify rules are syntactically valid**

```bash
semgrep --validate rules/pii-fields.yaml rules/insecure-config.yaml
```

Expected: `Validating rules... No errors found.`

- [ ] **Step 4: Smoke-test rules against a sample file**

Create a temp file and verify the rules fire:

```bash
cat > /tmp/test_pii.py << 'EOF'
import requests

ssn = input("Enter SSN: ")
card_number = "4111111111111111"
requests.post("https://api.example.com/store", data={"ssn": ssn}, verify=False)
EOF

semgrep --config rules/pii-fields.yaml --config rules/insecure-config.yaml /tmp/test_pii.py
```

Expected: At least 3 findings (ssn, card_number, verify=False).

- [ ] **Step 5: Run full suite to confirm no breakage**

```bash
pytest -v
```

Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add rules/pii-fields.yaml rules/insecure-config.yaml
git commit -m "feat: add Semgrep rules for PII variable name patterns and insecure TLS config flags"
```

---

## Task 9: Report Extension

**Files:**
- Modify: `src/audit_packs/report.py`
- Modify: `tests/test_report.py`

**Interfaces:**
- Consumes: `ScoredFinding`, `AdjudicationResult`, `ScoreComponents` from Tasks 5 and 7; existing `ControlFinding` for `gate_failed()` (unchanged)
- Produces:
  - Updated `build_comments(scored_findings: list[ScoredFinding], commit_sha: str) -> list[dict]`
  - New `build_summary_comment(all_scored: list[ScoredFinding], threshold: float, weights: dict) -> str`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_report.py`:

```python
# Add these imports at the top of test_report.py:
# from audit_packs.report import build_comments, build_summary_comment
# from audit_packs.models import Finding, ControlFinding, AdjudicationResult, AdjudicationMode
# from audit_packs.confidence import ScoreComponents, ScoredFinding, DEFAULT_WEIGHTS
# from audit_packs.evidence import PRContext

# These tests go in test_report.py — the existing tests for build_comments(control_findings)
# need updating since the signature now takes list[ScoredFinding]. Add below:

def _scored_finding(surfaced=True, judge_score=0.87, framework="gdpr",
                    control_id="Art-32-a", control_title="Pseudonymisation and Encryption",
                    severity="high", check_id="CKV_AWS_19", engine="checkov",
                    message="S3 bucket encryption disabled"):
    from audit_packs.models import Finding, ControlFinding, AdjudicationResult
    from audit_packs.confidence import ScoreComponents, ScoredFinding, DEFAULT_WEIGHTS, score_finding
    f = Finding(check_id, engine, "main.tf", 11, severity, message, "encrypted = false")
    cf = ControlFinding(f, framework, control_id, control_title)
    result = AdjudicationResult(
        control_finding=cf,
        detector_score=judge_score,
        verifier_argument="Data stored without encryption",
        adversarial_argument="This could be a test bucket",
        judge_score=judge_score,
        model_consensus=judge_score,
        rationale="Storing data at rest without encryption violates GDPR Art. 32(a).",
    )
    comps = ScoreComponents(
        rule_confidence=0.9, evidence_confidence=0.8, model_consensus=judge_score,
        historical_precision=0.78, control_severity=0.8, flow_confidence=0.9
    )
    fs = score_finding(result, comps, DEFAULT_WEIGHTS)
    return ScoredFinding(result=result, components=comps, finding_score=fs,
                          surfaced=surfaced, suppression_reason="" if surfaced else "low score")


def test_build_comments_includes_framework_and_control():
    from audit_packs.report import build_comments
    scored = [_scored_finding()]
    comments = build_comments(scored, "abc123")
    assert len(comments) == 1
    assert "GDPR" in comments[0]["body"] or "gdpr" in comments[0]["body"].lower()
    assert "Art-32-a" in comments[0]["body"]

def test_build_comments_includes_score_percentage():
    from audit_packs.report import build_comments
    scored = [_scored_finding(judge_score=0.87)]
    comments = build_comments(scored, "abc123")
    body = comments[0]["body"]
    assert "%" in body

def test_build_comments_includes_score_breakdown():
    from audit_packs.report import build_comments
    scored = [_scored_finding()]
    comments = build_comments(scored, "abc123")
    body = comments[0]["body"]
    assert "rule" in body and "evidence" in body and "consensus" in body

def test_build_comments_includes_rationale():
    from audit_packs.report import build_comments
    scored = [_scored_finding()]
    comments = build_comments(scored, "abc123")
    body = comments[0]["body"]
    assert "GDPR Art. 32(a)" in body

def test_build_comments_excludes_suppressed():
    from audit_packs.report import build_comments
    scored = [_scored_finding(surfaced=False)]
    comments = build_comments(scored, "abc123")
    assert comments == []

def test_build_summary_comment_contains_framework_row():
    from audit_packs.report import build_summary_comment
    from audit_packs.confidence import DEFAULT_WEIGHTS
    scored = [_scored_finding(framework="gdpr"), _scored_finding(framework="gdpr", surfaced=False)]
    summary = build_summary_comment(scored, threshold=0.70, weights=DEFAULT_WEIGHTS)
    assert "gdpr" in summary
    assert "1" in summary  # 1 suppressed

def test_build_summary_comment_shows_score_formula():
    from audit_packs.report import build_summary_comment
    from audit_packs.confidence import DEFAULT_WEIGHTS
    scored = [_scored_finding()]
    summary = build_summary_comment(scored, threshold=0.70, weights=DEFAULT_WEIGHTS)
    assert "0.20" in summary or "rule" in summary
    assert "Threshold" in summary or "threshold" in summary.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_report.py -v -k "build_comments_includes or build_summary"
```

Expected: FAIL — new `build_comments` signature and `build_summary_comment` not defined.

- [ ] **Step 3: Update `report.py`**

Replace `build_comments()` and add `build_summary_comment()` in `src/audit_packs/report.py`. Keep all other functions unchanged.

```python
# Replace the existing build_comments() function:

def build_comments(scored_findings: list, commit_sha: str) -> list[dict]:
    """Build PR review comments for surfaced ScoredFindings."""
    comments = []
    for sf in scored_findings:
        if not sf.surfaced:
            continue
        result = sf.result
        cf = result.control_finding
        f = cf.finding
        comps = sf.components
        score_pct = round(sf.finding_score * 100)

        breakdown = (
            f"rule {round(comps.rule_confidence * 100)}% · "
            f"evidence {round(comps.evidence_confidence * 100)}% · "
            f"consensus {round(comps.model_consensus * 100)}% · "
            f"history {round(comps.historical_precision * 100)}% · "
            f"severity {round(comps.control_severity * 100)}% · "
            f"flow {round(comps.flow_confidence * 100)}%"
        )

        body = (
            f"**[{cf.framework.upper()} / {cf.control_id} — {cf.control_title}]**  score: {score_pct}%\n"
            f"- Severity: `{f.severity}`  |  Engine: `{f.engine}` (`{f.check_id}`)\n"
            f"- Finding: {f.message}\n"
            f"- Score breakdown: {breakdown}\n"
            f"Evidence: `{f.evidence}`\n"
            f"Rationale: {result.rationale}"
        )
        comments.append({"path": f.file, "line": f.line, "side": "RIGHT", "body": body})
    return comments


def build_summary_comment(all_scored: list, threshold: float, weights: dict) -> str:
    """Build the summary comment posted once after inline comments."""
    from collections import defaultdict
    by_framework: dict[str, list] = defaultdict(list)
    for sf in all_scored:
        fw = sf.result.control_finding.framework
        by_framework[fw].append(sf)

    lines = ["## Audit Packs Summary", "| Framework | Findings | Suppressed | Avg Score |", "|---|---|---|---|"]
    total_surfaced = 0
    total_suppressed = 0

    for fw, sfs in sorted(by_framework.items()):
        surfaced = [s for s in sfs if s.surfaced]
        suppressed = [s for s in sfs if not s.surfaced]
        avg = round(sum(s.finding_score for s in surfaced) / len(surfaced) * 100) if surfaced else 0
        lines.append(f"| {fw} | {len(surfaced)} | {len(suppressed)} | {avg}% |")
        total_surfaced += len(surfaced)
        total_suppressed += len(suppressed)

    lines.append("")
    lines.append(
        f"Total: {total_surfaced} surfaced, {total_suppressed} suppressed (FP). "
        f"Threshold: {round(threshold * 100)}%."
    )
    weight_formula = " + ".join(
        f"{w}·{k}" for k, w in [
            ("rule", weights.get("rule", 0.20)),
            ("evidence", weights.get("evidence", 0.15)),
            ("consensus", weights.get("consensus", 0.25)),
            ("history", weights.get("history", 0.10)),
            ("severity", weights.get("severity", 0.10)),
            ("flow", weights.get("flow", 0.20)),
        ]
    )
    lines.append(f"Score = {weight_formula}")
    return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_report.py -v
```

Expected: All PASS (including existing tests — note: existing tests for `build_comments` with `ControlFinding` args will now fail and need updating).

Update the old `build_comments` tests in `test_report.py` to use `_scored_finding()` helpers. Look for any test calling `build_comments([ControlFinding(...)])` and change to `build_comments([_scored_finding(...)])`.

- [ ] **Step 5: Run full suite**

```bash
pytest -v
```

Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/audit_packs/report.py tests/test_report.py
git commit -m "feat: update build_comments() to take ScoredFindings with confidence badges; add build_summary_comment()"
```

---

## Task 10: CLI + Action Extension

**Files:**
- Modify: `src/audit_packs/cli.py`
- Modify: `action.yml`
- Create: `tests/test_cli_frameworks.py`

**Interfaces:**
- Consumes: All modules from Tasks 1–9
- Produces: Updated `analyze()` wiring evidence, agents, confidence; `normalize_frameworks()` for alias resolution; updated `action.yml` with new inputs.

- [ ] **Step 1: Write failing tests for framework normalization**

Create `tests/test_cli_frameworks.py`:

```python
import pytest
from audit_packs.cli import normalize_frameworks

def test_gdpr_normalized():
    assert normalize_frameworks("GDPR") == ["gdpr"]

def test_hipaa_lowercase():
    assert normalize_frameworks("hipaa") == ["hipaa"]

def test_soc2_alias():
    assert normalize_frameworks("SOC2") == ["soc2"]
    assert normalize_frameworks("soc-2") == ["soc2"]

def test_iso27001_aliases():
    assert normalize_frameworks("ISO27001") == ["iso27001"]
    assert normalize_frameworks("iso-27001") == ["iso27001"]

def test_pci_dss_aliases():
    assert normalize_frameworks("PCI-DSS") == ["pci-dss"]
    assert normalize_frameworks("pcidss") == ["pci-dss"]
    assert normalize_frameworks("pci_dss") == ["pci-dss"]

def test_nist_aliases():
    assert normalize_frameworks("NIST-800-53") == ["nist-800-53"]
    assert normalize_frameworks("nist800-53") == ["nist-800-53"]
    assert normalize_frameworks("nist") == ["nist-800-53"]

def test_fedramp_alias():
    assert normalize_frameworks("FedRAMP") == ["fedramp"]

def test_org_policy_aliases():
    assert normalize_frameworks("org-policy") == ["org-policy"]
    assert normalize_frameworks("org_policy") == ["org-policy"]
    assert normalize_frameworks("internal") == ["org-policy"]

def test_comma_separated():
    result = normalize_frameworks("GDPR,HIPAA")
    assert result == ["gdpr", "hipaa"]

def test_newline_separated():
    result = normalize_frameworks("GDPR\nHIPAA\nSOC2")
    assert result == ["gdpr", "hipaa", "soc2"]

def test_mixed_comma_and_newline():
    result = normalize_frameworks("GDPR\nHIPAA,SOC2")
    assert result == ["gdpr", "hipaa", "soc2"]

def test_unknown_framework_raises_value_error():
    with pytest.raises(ValueError, match="Unknown framework"):
        normalize_frameworks("UNKNOWN_FRAMEWORK")

def test_empty_tokens_skipped():
    result = normalize_frameworks("GDPR,,HIPAA")
    assert result == ["gdpr", "hipaa"]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_cli_frameworks.py -v
```

Expected: FAIL — `normalize_frameworks` not importable from `cli`.

- [ ] **Step 3: Add `normalize_frameworks()` to `cli.py`**

At the top of `cli.py`, add the alias map and function:

```python
_FRAMEWORK_ALIASES: dict[str, str] = {
    "gdpr": "gdpr",
    "hipaa": "hipaa",
    "soc2": "soc2", "soc-2": "soc2",
    "iso27001": "iso27001", "iso-27001": "iso27001",
    "pci-dss": "pci-dss", "pcidss": "pci-dss", "pci_dss": "pci-dss",
    "nist-800-53": "nist-800-53", "nist800-53": "nist-800-53", "nist": "nist-800-53",
    "fedramp": "fedramp",
    "org-policy": "org-policy", "org_policy": "org-policy", "internal": "org-policy",
}


def normalize_frameworks(raw: str) -> list[str]:
    """Parse FRAMEWORKS env (comma or newline separated) and resolve aliases."""
    tokens = [t.strip().lower() for t in raw.replace("\n", ",").split(",") if t.strip()]
    result = []
    for tok in tokens:
        if tok not in _FRAMEWORK_ALIASES:
            raise ValueError(
                f"Unknown framework: {tok!r}. Supported: {sorted(set(_FRAMEWORK_ALIASES.values()))}"
            )
        result.append(_FRAMEWORK_ALIASES[tok])
    return result
```

- [ ] **Step 4: Run framework normalization tests**

```bash
pytest tests/test_cli_frameworks.py -v
```

Expected: All PASS.

- [ ] **Step 5: Update `analyze()` to wire all new modules**

Replace the `analyze()` function in `cli.py`:

```python
def analyze(repo_dir, changed, packs_dir, rules_path, frameworks, adj_mode=AdjudicationMode.OFF,
            model_config=None, pr_context=None, codeql_sarif_dir="",
            precision_data=None, weights=None, threshold=0.70):
    """Run engines, enrich, adjudicate, score, and return ScoredFindings for diff-changed lines."""
    from audit_packs.agents import NoOpAgent
    from audit_packs.evidence import enrich, evidence_confidence
    from audit_packs.dataflow import extract_data_flows, flow_confidence
    from audit_packs.confidence import (
        ScoreComponents, apply_confidence_gate, get_historical_precision, control_severity_score,
    )
    from audit_packs.adjudicate import adjudicate as adj_finding
    from audit_packs.normalize import extract_rule_confidences

    if model_config is None:
        from audit_packs.adjudicate import load_model_config
        model_config = load_model_config()
    if precision_data is None:
        precision_data = {}
    if weights is None:
        from audit_packs.confidence import DEFAULT_WEIGHTS
        weights = DEFAULT_WEIGHTS

    # Run detection engines
    checkov_sarif = run_checkov(repo_dir)
    semgrep_sarif = run_semgrep(repo_dir, rules_path)
    codeql_sarif = read_codeql_sarif(codeql_sarif_dir) if codeql_sarif_dir else {"runs": []}

    # Run agent stubs (no-op in Phase 1)
    agent = NoOpAgent()
    changed_file_texts = {}
    for rel_path in changed:
        abs_path = os.path.join(repo_dir, rel_path)
        if os.path.isfile(abs_path):
            try:
                changed_file_texts[rel_path] = open(abs_path).read()
            except OSError:
                pass
    agent_sarif = agent.detect(changed_file_texts)

    rule_confidences: dict[str, float] = {}
    rule_confidences.update(extract_rule_confidences(semgrep_sarif))
    rule_confidences.update(extract_rule_confidences(codeql_sarif))

    findings = []
    findings += sarif_to_findings(checkov_sarif, "checkov")
    findings += sarif_to_findings(semgrep_sarif, "semgrep")
    findings += sarif_to_findings(codeql_sarif, "codeql")
    findings += sarif_to_findings(agent_sarif, "noop-agent")

    # Extract data flows per file (for flow_confidence)
    data_flows: dict[str, list] = {}
    for rel_path, file_text in changed_file_texts.items():
        lang = "python" if rel_path.endswith(".py") else "hcl" if rel_path.endswith(".tf") else "yaml"
        data_flows[rel_path] = extract_data_flows(file_text, lang)

    # Enrich findings and compute evidence_confidence per finding
    ev_conf_map: dict[int, float] = {}
    enriched_findings = []
    for f in findings:
        rel_path = _rel(f.file, repo_dir)
        file_text = changed_file_texts.get(rel_path, "")
        enriched = enrich(f, file_text, pr_context) if file_text else f
        ev_conf_map[id(enriched)] = evidence_confidence(enriched, pr_context)
        enriched_findings.append(enriched)

    # Filter to diff-changed lines
    in_diff = []
    for f in enriched_findings:
        rel_path = _rel(f.file, repo_dir)
        if f.line in changed.get(rel_path, set()):
            in_diff.append(replace(f, file=rel_path) if rel_path != f.file else f)

    # Map to control findings
    control_findings = map_findings(in_diff, packs_dir, frameworks)

    # Adjudicate each control finding
    pairs = []
    for cf in control_findings:
        finding = cf.finding
        result = adj_finding(cf, pr_context, adj_mode, model_config)

        rel_path = finding.file
        flows = data_flows.get(rel_path, [])
        f_conf = flow_confidence(flows, finding.line)
        ev_conf = ev_conf_map.get(id(finding), 0.4)
        rule_conf = rule_confidences.get(finding.check_id, 0.6)
        hist_prec = get_historical_precision(finding.check_id, cf.framework, precision_data)
        ctrl_sev = control_severity_score(finding.severity)

        components = ScoreComponents(
            rule_confidence=rule_conf,
            evidence_confidence=ev_conf,
            model_consensus=result.model_consensus,
            historical_precision=hist_prec,
            control_severity=ctrl_sev,
            flow_confidence=f_conf,
        )
        pairs.append((result, components))

    return apply_confidence_gate(pairs, threshold=threshold, mode=adj_mode, weights=weights)
```

Also add the import `from audit_packs.engines import read_codeql_sarif` at the top of `cli.py`.

- [ ] **Step 6: Update `main()` in `cli.py`**

Update `main()` to use the new wiring:

```python
def main() -> int:
    import json as _json
    from audit_packs.adjudicate import load_model_config
    from audit_packs.confidence import DEFAULT_WEIGHTS
    from audit_packs.report import build_summary_comment

    repo = os.environ["GITHUB_REPOSITORY"]
    token = os.environ["GITHUB_TOKEN"]
    pr_number = os.environ["PR_NUMBER"]
    base_ref = os.environ.get("BASE_REF", "origin/main")
    commit_sha = os.environ["GITHUB_SHA"]
    workspace = os.environ.get("GITHUB_WORKSPACE", ".")
    packs_dir = os.environ.get("PACKS_DIR", "/app/packs")
    rules_path = os.environ.get("RULES_PATH", "/app/rules")

    raw_frameworks = os.environ.get("FRAMEWORKS", "nist-800-53")
    try:
        frameworks = normalize_frameworks(raw_frameworks)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    fail_on = os.environ.get("FAIL_ON", "high")
    if fail_on not in SEVERITIES:
        print(f"Error: FAIL_ON='{fail_on}' is not valid. Choose from: {', '.join(SEVERITIES)}", file=sys.stderr)
        return 2

    scan_mode = os.environ.get("SCAN_MODE", "both").lower()
    if scan_mode not in _VALID_SCAN_MODES:
        print(f"Error: SCAN_MODE='{scan_mode}' is not valid.", file=sys.stderr)
        return 2

    emit_oscal = os.environ.get("EMIT_OSCAL", "true").lower() == "true"
    emit_coverage = os.environ.get("EMIT_COVERAGE", "true").lower() == "true"
    emit_sarif = os.environ.get("EMIT_SARIF", "true").lower() == "true"

    adj_mode_str = os.environ.get("ADJUDICATION_MODE", "off").lower()
    adj_mode = AdjudicationMode(adj_mode_str) if adj_mode_str in {m.value for m in AdjudicationMode} else AdjudicationMode.OFF

    threshold_str = os.environ.get("CONFIDENCE_THRESHOLD", "0.70")
    try:
        threshold = float(threshold_str)
    except ValueError:
        print(f"Error: CONFIDENCE_THRESHOLD='{threshold_str}' is not a valid float.", file=sys.stderr)
        return 2

    # Load score weights
    weights = DEFAULT_WEIGHTS
    score_weights_env = os.environ.get("SCORE_WEIGHTS", "")
    if score_weights_env:
        try:
            parsed = dict(pair.split(":") for pair in score_weights_env.split(","))
            weights = {k: float(v) for k, v in parsed.items()}
            if abs(sum(weights.values()) - 1.0) > 0.001:
                raise ValueError("weights must sum to 1.0")
        except Exception as exc:
            print(f"Error: SCORE_WEIGHTS invalid: {exc}", file=sys.stderr)
            return 2

    models_config_path = os.environ.get("AUDIT_MODELS_CONFIG", "audit-models.yaml")
    try:
        model_config = load_model_config(models_config_path)
    except ValueError as exc:
        print(f"Error loading model config: {exc}", file=sys.stderr)
        return 2

    codeql_sarif_dir = os.environ.get("CODEQL_SARIF_DIR", "")

    # Historical precision
    precision_path = os.path.join(".audit-cache", "precision.json")
    precision_data: dict = {}
    if os.path.exists(precision_path):
        try:
            with open(precision_path) as fh:
                precision_data = _json.load(fh)
        except Exception:
            pass

    audit_confirm = os.environ.get("AUDIT_CONFIRM", "")
    if audit_confirm:
        from audit_packs.confidence import update_precision
        import tempfile
        for pair in audit_confirm.split(","):
            pair = pair.strip()
            if ":" in pair:
                chk, fw = pair.split(":", 1)
                precision_data = update_precision(chk.strip(), fw.strip(), precision_data)
        os.makedirs(".audit-cache", exist_ok=True)
        with tempfile.NamedTemporaryFile("w", dir=".audit-cache", delete=False, suffix=".tmp") as fh:
            _json.dump(precision_data, fh)
            tmp = fh.name
        os.replace(tmp, precision_path)

    # Fetch PR context (best-effort)
    pr_context = None
    if adj_mode is not AdjudicationMode.OFF:
        try:
            from audit_packs.evidence import fetch_pr_context
            pr_context = fetch_pr_context(repo, pr_number, token)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("Could not fetch PR context: %s", exc)

    gate_tripped = False

    if scan_mode in ("diff", "both"):
        diff_text = run_git_diff(workspace, base_ref)
        changed = parse_unified_diff(diff_text)
        scored = analyze(
            workspace, changed, packs_dir, rules_path, frameworks,
            adj_mode=adj_mode, model_config=model_config, pr_context=pr_context,
            codeql_sarif_dir=codeql_sarif_dir, precision_data=precision_data,
            weights=weights, threshold=threshold,
        )
        from audit_packs.report import build_comments, build_summary_comment
        comments = build_comments(scored, commit_sha)
        summary = build_summary_comment(scored, threshold=threshold, weights=weights)
        if comments:
            post_review(comments, summary, repo=repo, pr_number=pr_number, token=token, commit_sha=commit_sha)
        surfaced_cfs = [sf.result.control_finding for sf in scored if sf.surfaced]
        if gate_failed(surfaced_cfs, fail_on):
            gate_tripped = True

    if scan_mode in ("full", "both"):
        control_statuses = assess(workspace, packs_dir, rules_path, frameworks, adj_mode=adj_mode)
        if emit_oscal:
            oscal_path = os.path.join(workspace, "oscal.json")
            oscal_data = to_assessment_results(control_statuses)
            with open(oscal_path, "w") as fh:
                _json.dump(oscal_data, fh, indent=2)
            print(f"::notice::OSCAL assessment-results written to {oscal_path}")
        if emit_coverage:
            for fmt in ("md", "html"):
                cov_path = os.path.join(workspace, f"coverage.{fmt}")
                content = build_coverage_matrix(control_statuses, fmt=fmt)
                with open(cov_path, "w") as fh:
                    fh.write(content)
            print(f"::notice::Coverage matrix written to {os.path.join(workspace, 'coverage.md')}")
            write_job_summary(build_coverage_matrix(control_statuses, fmt="md"))
        if emit_sarif:
            all_cfs = [cf for cs in control_statuses for cf in cs.findings]
            sarif_path = os.path.join(workspace, "audit-packs.sarif")
            with open(sarif_path, "w") as fh:
                _json.dump(build_sarif(all_cfs), fh, indent=2)
            print(f"::notice::Aggregate SARIF written to {sarif_path}")

    return 1 if gate_tripped else 0
```

- [ ] **Step 7: Update `action.yml`**

Add the new inputs to `action.yml`. The existing `frameworks`, `fail-on`, `base-ref`, `scan-mode`, `emit-oscal`, `emit-coverage`, `emit-sarif`, `adjudication-mode` inputs are carried forward. New inputs:

```yaml
# In action.yml, update the inputs section:
inputs:
  frameworks:
    description: |
      Newline-separated (or comma-separated) list of framework IDs to assess.
      Supported: GDPR, HIPAA, SOC2, ISO27001, PCI-DSS, NIST-800-53, FedRAMP, org-policy.
    required: true

  min-confidence:
    description: "Composite score threshold (0.0–1.0). Findings below this are suppressed in enforce mode."
    default: "0.70"

  adjudication-mode:
    description: "off (no LLM calls) | advisory (score shown, nothing suppressed) | enforce (suppress below threshold)"
    default: "off"

  models-config:
    description: |
      Path to a model routing YAML file (relative to repo root).
      Defines provider, model, base_url, and api_key_env for each role.
      Supports cloud APIs and local endpoints (Ollama, vLLM).
      If omitted, uses audit-models.yaml at repo root if present,
      otherwise falls back to built-in defaults (cloud models).
    default: "audit-models.yaml"

  detector-model:
    description: "Override the detector role's model (sets DETECTOR_MODEL env)."
    default: ""

  verifier-model:
    description: "Override the verifier role's model (sets VERIFIER_MODEL env)."
    default: ""

  adversarial-model:
    description: "Override the adversarial role's model (sets ADVERSARIAL_MODEL env)."
    default: ""

  judge-model:
    description: "Override the judge role's model (sets JUDGE_MODEL env)."
    default: ""

  codeql-sarif:
    description: |
      Path to directory of CodeQL SARIF files from github/codeql-action/analyze.
      If absent or empty, CodeQL findings are skipped (graceful degradation).
    default: ""

  ast-rules:
    description: "Path to Tree-sitter AST rule scripts directory (Phase 2 — reserved; ignored in Phase 1)."
    default: "ast-rules"

  fail-on:
    description: "Minimum severity that blocks the PR: low | medium | high | critical"
    default: "high"

  base-ref:
    description: "Git ref to diff against."
    default: "origin/main"

  scan-mode:
    description: "diff | full | both"
    default: "both"

  emit-oscal:
    description: "Emit OSCAL assessment-results JSON"
    default: "true"

  emit-coverage:
    description: "Emit coverage matrix as Markdown and HTML"
    default: "true"

  emit-sarif:
    description: "Emit aggregate SARIF for upload"
    default: "true"

runs:
  using: "docker"
  image: "Dockerfile"
  env:
    FRAMEWORKS:           ${{ inputs.frameworks }}
    CONFIDENCE_THRESHOLD: ${{ inputs.min-confidence }}
    ADJUDICATION_MODE:    ${{ inputs.adjudication-mode }}
    AUDIT_MODELS_CONFIG:  ${{ inputs.models-config }}
    DETECTOR_MODEL:       ${{ inputs.detector-model }}
    VERIFIER_MODEL:       ${{ inputs.verifier-model }}
    ADVERSARIAL_MODEL:    ${{ inputs.adversarial-model }}
    JUDGE_MODEL:          ${{ inputs.judge-model }}
    FAIL_ON:              ${{ inputs.fail-on }}
    BASE_REF:             ${{ inputs.base-ref }}
    SCAN_MODE:            ${{ inputs.scan-mode }}
    EMIT_OSCAL:           ${{ inputs.emit-oscal }}
    EMIT_COVERAGE:        ${{ inputs.emit-coverage }}
    EMIT_SARIF:           ${{ inputs.emit-sarif }}
    CODEQL_SARIF_DIR:     ${{ inputs.codeql-sarif }}
    AST_RULES_DIR:        ${{ inputs.ast-rules }}
    GITHUB_TOKEN:         ${{ github.token }}
    PR_NUMBER:            ${{ github.event.pull_request.number }}
```

- [ ] **Step 8: Run full suite**

```bash
pytest -v
```

Expected: All PASS with `ADJUDICATION_MODE=off` (default in CI).

- [ ] **Step 9: Verify integration test still passes**

```bash
pytest tests/test_integration.py -v
```

Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add src/audit_packs/cli.py action.yml tests/test_cli_frameworks.py
git commit -m "feat: wire evidence, dataflow, agents, confidence, CodeQL into CLI; add framework name normalisation; update action.yml"
```

---

## Self-Review

**Spec coverage check:**

| Spec section | Task covering it |
|---|---|
| §2 Evidence enrichment — PRContext, fetch_pr_context, extract_doc_context, enrich | Task 3 |
| §2 Evidence confidence scoring | Task 3, 5 |
| §2b DataFlow — extract_data_flows, flow_confidence | Task 2 |
| §2c CodeQL — read_codeql_sarif, graceful degradation | Task 4 |
| §2c PathNode, evidence_path on Finding | Tasks 1, 4 |
| §2c extract_rule_confidences | Task 4 |
| §3 4-role sequential ensemble | Task 7 |
| §3.1 Model routing YAML + env var overrides | Task 7 |
| §3.1 Air-gapped / ollama support | Task 7 |
| §3.4 Failure handling table | Task 7 |
| §3.5 Caching by sha256 key | Task 7 |
| §3.6 Modes (off/advisory/enforce) | Tasks 5, 7 |
| §4 Composite scoring formula | Task 5 |
| §4.2 All 6 score components | Task 5 |
| §4.2 Historical precision + AUDIT_CONFIRM | Tasks 5, 10 |
| §4.4 Gate logic all 3 modes | Task 5 |
| §4.5 PR comment format with score breakdown | Task 9 |
| §4.5 Summary comment table + formula | Task 9 |
| §5 DetectionAgent ABC + NoOpAgent | Task 6 |
| §6.2 action.yml new inputs | Task 10 |
| §6.3 Framework name normalisation | Task 10 |
| New Semgrep rules (pii-fields, insecure-config) | Task 8 |
| models.py AdjudicationMode in models (not adjudicate) | Task 1 |
| Backward compat: Finding with defaults | Task 1 |
| IO boundary: only engines, report, evidence do IO | All tasks |

**Gaps confirmed: None.** All Phase 1 deliverables are covered.

**Placeholder scan:** None present. All steps include exact code.

**Type consistency check:**
- `AdjudicationResult.control_finding: ControlFinding` ✓ used in Tasks 7, 9, 10
- `ScoredFinding.result: AdjudicationResult` ✓ Tasks 5, 9, 10
- `flow_confidence(flows: list[DataFlow], finding_line: int) -> float` ✓ Tasks 2, 10
- `evidence_confidence(finding: Finding, pr_context: PRContext | None) -> float` ✓ Tasks 3, 10
- `build_comments(scored_findings: list[ScoredFinding], ...)` ✓ Tasks 9, 10
- `normalize_frameworks(raw: str) -> list[str]` ✓ Tasks 10

---

**Plan complete.** Two execution options:

**1. Subagent-Driven (recommended)** — Fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
