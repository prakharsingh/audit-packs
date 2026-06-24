# Compliance Framework Extension — Design Spec

**Date:** 2026-06-25
**Scope:** Extend audit-packs to cover GDPR, HIPAA, SOC 2, ISO 27001, PCI-DSS, NIST 800-53, FedRAMP, and Internal Org Policy with a two-phase architecture: prompt-agent ensemble (Phase 1, impl plan attached) and detection agents (Phase 2, spec only).

---

## Background

The MVP (see `docs/superpowers/plans/2026-06-24-audit-packs-mvp.md`) ships with:
- All 8 framework packs as YAML crosswalks onto NIST 800-53
- A single-model binary adjudicator (`adjudicate.py`)
- Coverage tracking (`coverage.py`) and OSCAL export (`oscal.py`)
- 5 authored Semgrep rules covering IaC findings

This spec extends those capabilities with a confidence-weighted judge ensemble, evidence enrichment, and a Phase 2 stub for framework-specific detection agents.

---

## Architecture

Data flow analysis splits the pipeline into two early branches that merge before detection:

```
GitHub PR
    │
    ├───────────────────────────────┐
    ▼                               ▼
Change Extraction               Data Flow Analysis
diff.py (unchanged)             dataflow.py (NEW)
    │                               │
    │                    ┌──────────┴──────────┐
    │                    │ Phase 1:             │ Phase 2:
    │                    │ flow evidence        │ DataFlowAgent SARIF
    │                    │ (evidence.py)        │ (agents.py)
    │                    └──────────┬──────────┘
    └──────────────┬────────────────┘
                   ▼
    Detection Agent Stub        agents.py           (NEW — no-op / DataFlowAgent in Phase 2)
                   │
                   ▼
    Engine Detection            engines.py          (+ Semgrep rules + AST rules + CodeQL SARIF reader)
                   │
                   ▼
    SARIF Normalize             normalize.py        (unchanged)
                   │
                   ▼
    Evidence Enrichment         evidence.py         (NEW — PR body, doc comments, flow context)
                   │
                   ▼
    Diff Filter + Orchestration cli.py              (extended — wires dataflow, evidence, agents, confidence)
                   │
                   ▼
    Crosswalk Mapping           packs.py            (unchanged — produces ControlFindings)
                   │
                   ▼
    Prompt Agent Ensemble       adjudicate.py       (extended — framework context + float score)
                   │
                   ▼
    Confidence Gate             confidence.py       (NEW — 6-component composite score + gate)
                   │
                   ▼
    Coverage + OSCAL            coverage.py / oscal.py  (unchanged)
                   │
                   ▼
    GitHub Review Comments      report.py           (extended — show score breakdown)
```

**IO boundary rule (updated):** `engines.py`, `report.py`, and `evidence.py` are the only modules permitted to make subprocess or HTTP calls. Everything else — including `dataflow.py` — is pure Python testable without network or installed tools.

---

## Section 1: Framework Packs (already complete)

All 8 framework packs exist in `packs/`:

| Pack file | Type | Notes |
|---|---|---|
| `nist-800-53.yaml` | Canonical | 22 controls, 30+ check IDs across 5 Semgrep rules |
| `soc2.yaml` | Crosswalk → NIST | Full TSC coverage; manual controls marked `assessment: manual` |
| `gdpr.yaml` | Crosswalk → NIST | Arts. 25, 30, 32 |
| `hipaa.yaml` | Crosswalk → NIST | §164.312 sub-parts |
| `iso27001.yaml` | Crosswalk → NIST | ISO/IEC 27001:2022 Annex A |
| `pci-dss.yaml` | Crosswalk → NIST | PCI-DSS v4.0 requirements |
| `fedramp.yaml` | Crosswalk → NIST | FedRAMP Moderate baseline |
| `org-policy.yaml` | Crosswalk → NIST | Customizable internal controls |

No changes required to pack files for Phase 1. Phase 2 detection agents add a `custom_rules:` block to `org-policy.yaml`.

---

## Section 2: Evidence Enrichment (`evidence.py` — new)

**Purpose:** Attach non-SARIF context to each `Finding` before adjudication so the judge ensemble has richer signal.

**Three evidence sources:**

1. **Code + config Semgrep rules** — new rules targeting source files (not IaC): PII variable name patterns (`ssn`, `dob`, `card_number`, `passport_no`), insecure config flags (`ssl_verify=False`, `verify=False`, `tls_enabled=False`). These produce standard `Finding` objects through the existing normalize pipeline. New rule files: `rules/pii-fields.yaml`, `rules/insecure-config.yaml`.

2. **PR description + commit messages** — fetched once from GitHub API at run start. Summarized (first 500 chars of PR body, last 5 commit message subjects). Stored as `PRContext` and passed to all judge calls.

3. **Inline doc comments** — for each changed file, extract the nearest docstring or block comment within ±10 lines of the finding. `ast` module for Python files, regex for HCL/YAML/JSON. Attached to `Finding` as `doc_context: str`.

**New dataclasses:**

```python
@dataclass(frozen=True)
class PRContext:
    pr_body: str                      # truncated to 500 chars
    commit_messages: tuple[str, ...]  # last 5 subjects

def fetch_pr_context(repo: str, pr_number: str, token: str) -> PRContext: ...

def extract_doc_context(file_text: str, line: int) -> str: ...

def enrich(finding: Finding, changed_file_text: str, pr_context: PRContext) -> Finding:
    # uses dataclasses.replace() to return a NEW Finding with doc_context set
    # (Finding is frozen — never mutated in place)
```

**`Finding` model change — authoritative definition (Phase 1 adds two fields):**

```python
@dataclass(frozen=True)
class Finding:
    # Existing fields (unchanged):
    check_id: str
    engine: str            # "checkov" | "semgrep" | "ast" | "codeql"
    file: str
    line: int
    severity: str          # "low" | "medium" | "high" | "critical"
    message: str
    evidence: str          # SARIF code snippet; enrich() appends flow chain text
    # New fields (Phase 1 — backward compatible: defaults preserve existing behaviour):
    doc_context: str = ""                      # nearest docstring/comment within ±10 lines
    evidence_path: tuple["PathNode", ...] = ()  # taint chain from CodeQL codeFlows; () if none
```

`enrich()` uses `dataclasses.replace(finding, doc_context=..., evidence=...)`. It does **not** discard the original `evidence` string — it appends the data-flow chain text to it (e.g. `original_snippet + "\n[DataFlow] user_input (L12) → db_write (L19)"`). `Finding` is frozen; `enrich()` always returns a new instance.

**IO boundary note:** `evidence.py` is added as a third permitted IO module alongside `engines.py` and `report.py`. All other new modules (`dataflow.py`, `confidence.py`, `agents.py`) are pure Python, testable without network access or installed tools. This intentionally relaxes the MVP plan's two-module IO boundary.

---

## Section 2b: Data Flow Analysis (`dataflow.py` — new)

**Purpose:** Extract source → transform → sink chains from changed file content. Pure Python, no subprocess, no HTTP. Operates on the raw text of each changed file (passed by `cli.py` after reading from disk).

### Data flow model

```python
@dataclass(frozen=True)
class DataFlow:
    source_line: int        # line where sensitive data enters
    source_type: str        # "user_input" | "db_read" | "env_var" | "api_response"
    transforms: tuple[str, ...] # e.g. ("encrypt", "mask") — empty if none
    sink_line: int          # line where data is written/transmitted
    sink_type: str          # "db_write" | "api_call" | "log" | "response"
    has_transform: bool     # True if any transform detected between source and sink
```

### Detection scope

**Phase 1 — intra-function, intra-file only.** `dataflow.py` walks the AST of each changed Python file (stdlib `ast`) and applies regex patterns to HCL/YAML/JSON. It does not resolve imports or trace across file boundaries.

**Source patterns:**
- Python: `request.data`, `request.form`, `input()`, `os.environ`, ORM `.get()` / `.filter()` calls on known model names (`User`, `Patient`, `Customer`)
- HCL: `var.*`, `data "aws_secretsmanager_secret"`, resource attribute reads

**Transform patterns:**
- Python: calls to `encrypt`, `mask`, `hash`, `anonymise`, `redact`, `bcrypt`, `hashlib.*` within the same function scope as the source
- HCL: `kms_key_id`, `encrypted = true`

**Sink patterns:**
- Python: `db.session.add()`, `.save()`, `requests.post/put`, `logging.*`, `print()`, `response.json()`
- HCL: resource blocks that write (`aws_s3_bucket_object`, `aws_rds_cluster`, `aws_lambda_function` env)

### Interface

```python
def extract_data_flows(file_text: str, language: str) -> list[DataFlow]:
    """language: 'python' | 'hcl' | 'yaml' | 'json'"""

def flow_confidence(flows: list[DataFlow], finding_line: int) -> float:
    """
    Compute flow_confidence for the scoring formula.

    Algorithm:
    1. Restrict to flows where source_line or sink_line is within ±50 lines of finding_line.
    2. If no flows are in range: return 0.5 (neutral — no data-flow signal).
    3. Among in-range flows, select the one with minimum distance to finding_line,
       where distance = min(abs(source_line - finding_line), abs(sink_line - finding_line)).
       Tie-break: prefer flows where has_transform=False (more suspicious).
    4. Classify the selected flow:
       - has_transform=False AND both source_line and sink_line in range: return 0.9
         (unprotected sensitive flow — strong TP signal)
       - has_transform=False AND only one end in range:              return 0.7
         (partial unprotected flow — moderate TP signal)
       - has_transform=True AND both ends in range:                  return 0.2
         (protected flow — strong FP signal; data is encrypted/masked)
       - has_transform=True AND only one end in range:               return 0.5
         (partial protected flow — neutral)
    """
```

### Phase 1 output: evidence attachment

`cli.py` calls `extract_data_flows()` on each changed file and passes the result to `evidence.py`'s `enrich()`. The flow chain is serialised as a string appended to `Finding.evidence`, e.g.:

```
[DataFlow] user_input (L12) → (no transform) → db_write (L19)
```

This feeds both the judge prompt and the `flow_confidence` scoring component.

### Phase 2 output: SARIF findings (`DataFlowAgent`)

`DataFlowAgent.detect()` emits a SARIF result for every `DataFlow` where `has_transform=False` and both source and sink are classified as sensitive. SARIF `ruleId: "DFA-001"` (unprotected-sensitive-flow). The canonical NIST pack gains entries:

```yaml
- id: SC-13
  checks:
    - { engine: dataflow-agent, ids: [DFA-001] }
- id: SC-28
  checks:
    - { engine: dataflow-agent, ids: [DFA-001] }
```

Cross-file analysis (following imports, tracing across module boundaries) is handled by CodeQL in Section 2c.

---

## Section 2c: Enhanced Detection Layer — CodeQL + AST Rules + Evidence Paths

### 2c.1 Overview

Four detection sources feed the SARIF normalizer, in order of semantic depth:

| Source | Depth | Evidence quality | Phase |
|---|---|---|---|
| Checkov | Resource-level IaC | Config value (single line) | MVP (done) |
| Semgrep rules | Intra-file pattern | Code snippet | MVP (done) |
| AST rules (Tree-sitter) | Structural / multi-node | Node path within file | **Phase 2** |
| CodeQL | Cross-file semantic | Full taint path (source → sink) | Phase 1 |

All four emit SARIF. `normalize.py` extracts the richest available evidence from each, including CodeQL `codeFlows` as structured `PathNode` chains.

### 2c.2 CodeQL Integration

**Architecture decision:** CodeQL runs as a separate GitHub Actions step *before* audit-packs and writes SARIF to a directory. audit-packs reads those files via the `codeql-sarif` input. audit-packs does **not** invoke the CodeQL CLI as a subprocess — CodeQL is a large, slow binary with its own database build step, and it is already a first-class GitHub Actions citizen.

**Updated GitHub Actions usage:**

```yaml
steps:
  - uses: actions/checkout@v4
    with:
      fetch-depth: 0

  - uses: github/codeql-action/init@v3
    with:
      languages: python, javascript, go
      queries: security-extended   # includes taint-tracking queries

  - uses: github/codeql-action/analyze@v3
    with:
      output: codeql-sarif/
      upload: false               # audit-packs posts comments; skip default upload

  - uses: company/audit-packs@v2
    with:
      frameworks: |
        GDPR
        HIPAA
      codeql-sarif: codeql-sarif/   # directory of .sarif files
      min-confidence: 0.80
```

**`engines.py` addition:**

```python
def read_codeql_sarif(sarif_dir: str) -> dict:
    """Merge all .sarif files in sarif_dir into a single SARIF dict."""
```

Pure file I/O — `engines.py` is the permitted IO boundary. Returns `{"runs": []}` if directory is absent or empty (CodeQL step skipped = graceful degradation).

**CodeQL queries of interest for compliance:**

| Query | Framework controls |
|---|---|
| `python/CWE-312` — cleartext storage of sensitive info | SC-28, GDPR Art-32-a, HIPAA §164.312(a)(2)(iv) |
| `python/CWE-319` — cleartext transmission | SC-8, GDPR Art-32-b |
| `python/CWE-798` — hardcoded credentials | IA-5 |
| `javascript/CWE-079` — XSS | SC-8 |
| `go/CWE-022` — path traversal | AC-3 |

These map directly to existing NIST 800-53 controls via the canonical pack — no pack changes required. `engines.py` tags CodeQL findings with `engine: "codeql"` so `packs.py` can index them.

### 2c.3 AST Rules (Tree-sitter) — Phase 2

> **Deferred from Phase 1.** Tree-sitter requires compiling native C grammar libraries per language (Python, HCL, etc.) and adding a grammar build step to the Docker image. This is a meaningful standalone dependency that deserves its own implementation cycle. The rule interface below is the Phase 2 contract; the `ast-rules/` directory and `engines.py`'s `run_ast_rules()` are Phase 2 deliverables. The `ast-rules` action input is reserved but ignored in Phase 1.

**Why Tree-sitter over Semgrep patterns:** Semgrep patterns match linear code. Tree-sitter gives a full parse tree — enabling structural rules like "function takes a parameter named `user_data` and passes it to a sink without calling any function in `{encrypt, mask, anonymise}`" across nested scopes. These rules are not expressible as Semgrep patterns.

**New directory:** `ast-rules/` — Python scripts, one per rule.

**Rule interface:**

```python
# ast-rules/unmasked-pii-sink.py
RULE_ID = "AST-001"
LANGUAGES = ["python"]
CONFIDENCE = "HIGH"       # metadata.confidence for rule_confidence scoring
DESCRIPTION = "PII-named variable reaches a sink without masking."

def detect(tree, source_text: str, filename: str) -> list[dict]:
    """
    Returns list of SARIF-compatible result dicts:
    [{"ruleId": RULE_ID, "level": "error", "message": {...}, "locations": [...]}]
    """
```

**`engines.py` addition:**

```python
def run_ast_rules(target_dir: str, rules_dir: str) -> dict:
    """
    Walk target_dir, parse each supported file with Tree-sitter,
    run all rule scripts in rules_dir, return merged SARIF dict.
    engine tag: "ast"
    """
```

**Planned rules (Phase 1):**

| Rule ID | Pattern | Controls |
|---|---|---|
| `AST-001` | PII-named var → sink, no masking in scope | SC-28, GDPR Art-32-a |
| `AST-002` | DB query with user-controlled input, no parameterisation | AC-3 |
| `AST-003` | Logging call with object containing PII-named fields | AU-3, GDPR Art-30 |
| `AST-004` | Decorator-less public endpoint returning model with PII fields | SC-8 |

### 2c.4 Evidence Paths (`PathNode` — extending `models.py` and `normalize.py`)

**Problem:** Current `Finding.evidence` is a single string (the triggering code line). For CodeQL taint findings and AST structural findings, the evidence is a *path* — a sequence of nodes through the code that explains how data flows from source to sink.

**New model type:**

```python
@dataclass(frozen=True)
class PathNode:
    file: str
    line: int
    snippet: str          # source text of the relevant expression
    description: str      # human-readable step label ("source", "passes to", "reaches sink")

# Finding gains one new field (backward compatible — default empty):
@dataclass(frozen=True)
class Finding:
    # ... existing fields unchanged ...
    evidence_path: tuple[PathNode, ...] = ()
```

**`normalize.py` extension:** For each SARIF result, check for `codeFlows[0].threadFlows[0].locations`. If present, build `PathNode` tuples from each location's `physicalLocation` + `message.text`. Findings without `codeFlows` get `evidence_path = ()` (unchanged behaviour).

**Evidence path in LLM prompts:** The judge ensemble formats the path as a numbered chain:

```
Evidence path (CodeQL taint trace):
  1. [models.py:14] user_id = request.args.get("id")   ← source: user-controlled input
  2. [queries.py:42] result = db.execute(f"SELECT * FROM users WHERE id={user_id}")  ← sink: unsanitised SQL
```

This dramatically improves judge reasoning quality — the model sees exactly why CodeQL flagged the finding, not just the sink line.

### 2c.5 LLM Verification of Detection Layer Output

The four-role ensemble (Section 3) operates identically regardless of which engine produced the finding. The key difference is prompt richness:

- **Checkov finding:** judge sees one config line
- **Semgrep finding:** judge sees a code snippet
- **AST rule finding:** judge sees the structural path within the file
- **CodeQL finding:** judge sees the full cross-file taint path

Higher evidence quality → higher `evidence_confidence` score → higher composite `FindingScore`. False positives from CodeQL (which does produce them) are suppressed by the ensemble when the taint path doesn't actually reach a sensitive sink as claimed.

---

## Section 3: Prompt Agent Ensemble (extending `adjudicate.py`)

### 3.1 Model Routing

All four roles are fully user-configurable. The routing config is a YAML file (`audit-models.yaml` at the repo root by default; overridable via the `models-config` action input or `AUDIT_MODELS_CONFIG` env var). Every field except `model` has a sensible default so users only specify what they change.

**Full schema:**

```yaml
models:
  detector:
    provider: openai          # openai | anthropic | google | ollama | openai-compatible
    model: gpt-5
    base_url: null            # set for local/self-hosted endpoints
    api_key_env: OPENAI_API_KEY  # env var to read the API key from

  verifier:
    provider: anthropic
    model: claude-opus
    base_url: null
    api_key_env: ANTHROPIC_API_KEY

  adversarial:
    provider: google
    model: gemini-3-pro
    base_url: null
    api_key_env: GOOGLE_API_KEY

  judge:
    provider: openai
    model: gpt-5
    base_url: null
    api_key_env: OPENAI_API_KEY
```

**Built-in defaults** (used when `audit-models.yaml` is absent and no per-role env vars set):

| Role | Provider | Model |
|---|---|---|
| `detector` | `openai` | `gpt-4o` |
| `verifier` | `anthropic` | `claude-opus-4-5` |
| `adversarial` | `google` | `gemini-1.5-pro` |
| `judge` | `openai` | `gpt-4o` |

**Model config error handling (validated at startup, before any LLM calls):**
- `audit-models.yaml` absent → silently use built-in defaults.
- `audit-models.yaml` exists but is invalid YAML → `ValueError` with file path + parse error message; action exits non-zero.
- A role's `provider` value not in `{openai, anthropic, google, ollama, openai-compatible}` → `ValueError` naming the role and the unsupported value.
- A role key absent from the file → use built-in default for that role (partial config is valid).
- `api_key_env` set but env var not found at call time → `ValueError` at adjudication time naming the missing variable.

**Provider dispatch in `adjudicate.py`:**

| `provider` value | Client used | Notes |
|---|---|---|
| `openai` | `openai.OpenAI(base_url=..., api_key=...)` | Default `base_url` is OpenAI's API |
| `anthropic` | `anthropic.Anthropic(api_key=...)` | Native Anthropic client |
| `google` | `google.generativeai` | Native Gemini client |
| `ollama` | `openai.OpenAI(base_url=base_url, api_key="ollama")` | OpenAI-compatible; `base_url` required |
| `openai-compatible` | `openai.OpenAI(base_url=base_url, api_key=...)` | vLLM, LM Studio, Azure OpenAI, Groq, etc. |

`base_url` overrides the default for any provider — e.g. `provider: openai` with `base_url: https://your-azure-endpoint` reaches Azure OpenAI. `api_key_env: ""` (empty string) means no key is sent (valid for some local servers).

**Air-gapped / local-model config** (all roles on Ollama, self-hosted runner):

```yaml
models:
  detector:
    provider: ollama
    model: llama3.3:70b
    base_url: http://localhost:11434/v1

  verifier:
    provider: ollama
    model: mistral:7b
    base_url: http://localhost:11434/v1

  adversarial:
    provider: ollama
    model: qwen2.5:32b
    base_url: http://localhost:11434/v1

  judge:
    provider: ollama
    model: llama3.3:70b
    base_url: http://localhost:11434/v1
```

No cloud credentials required. No data leaves the runner. Works with any self-hosted GitHub Actions runner that has Ollama (or vLLM) on `localhost` or a network-adjacent host.

**Individual env var overrides** (take precedence over YAML file for rapid iteration):
`DETECTOR_MODEL`, `DETECTOR_PROVIDER`, `DETECTOR_BASE_URL`,
`VERIFIER_MODEL`, `VERIFIER_PROVIDER`, `VERIFIER_BASE_URL`,
`ADVERSARIAL_MODEL`, `ADVERSARIAL_PROVIDER`, `ADVERSARIAL_BASE_URL`,
`JUDGE_MODEL`, `JUDGE_PROVIDER`, `JUDGE_BASE_URL`.

### 3.2 Pipeline — Sequential Role-Based Debate

The ensemble is **not** a parallel fan-out. It is a three-round sequential pipeline with one parallel step:

```
Finding + ControlFinding + Evidence
         │
         ▼ Round 1
    ┌─────────────┐
    │  Detector   │  GPT-5 — initial assessment + confidence
    └─────────────┘
         │  (detector_score, detector_assessment)
         ▼ Round 2 (parallel)
    ┌──────────────┐    ┌─────────────────┐
    │   Verifier   │    │   Adversarial   │
    │ Claude Opus  │    │ Gemini-3-Pro    │
    │ argues TP    │    │ argues FP       │
    └──────────────┘    └─────────────────┘
         │  (verifier_argument)   │  (adversarial_argument)
         └──────────┬─────────────┘
                    ▼ Round 3
             ┌────────────┐
             │   Judge    │  GPT-5 — weighs debate, returns final score
             └────────────┘
                    │
             AdjudicationResult
```

**Round 1 — Detector prompt:**
```
System: You are a {framework} compliance expert. Assess this finding.
        Return JSON: {"confidence": <0.0-1.0>, "assessment": "<2-3 sentences>"}

User:   Control: {control_id} — {control_title}
        Finding: {check_id} on {file}:{line} — {message}
        Evidence: {evidence}  |  Flow: {data_flow_chain}
        PR context: {pr_body}  |  Doc comment: {doc_context}
```

**Round 2 — Verifier prompt (parallel with Adversarial):**
```
System: You are a strict {framework} compliance auditor. Argue why the
        following finding IS a genuine violation. Be specific about which
        requirement is violated and why the code evidence supports it.
        Return JSON: {"argument": "<argument>", "strength": <0.0-1.0>}

User:   [full finding context + detector assessment]
```

**Round 2 — Adversarial prompt (parallel with Verifier):**
```
System: You are a defence counsel reviewing a compliance finding. Argue why
        this finding is a FALSE POSITIVE — find mitigating factors, alternative
        interpretations, or missing context that would exonerate the code.
        Return JSON: {"argument": "<argument>", "strength": <0.0-1.0>}

User:   [full finding context + detector assessment]
```

**Round 3 — Judge prompt:**
```
System: You are a senior {framework} compliance judge. You have received a
        detector assessment, a prosecution argument, and a defence argument.
        Weigh the evidence and return a final confidence score.
        Return JSON: {"confidence": <0.0-1.0>, "rationale": "<one sentence>"}

User:   Detector score: {detector_score}
        Prosecution (verifier): {verifier_argument}
        Defence (adversarial): {adversarial_argument}
        [full finding context]
```

### 3.3 Return Type

```python
@dataclass(frozen=True)
class AdjudicationResult:
    control_finding: ControlFinding
    detector_score: float           # Round 1 — GPT-5 initial confidence
    verifier_argument: str          # Round 2 — Claude Opus prosecution
    adversarial_argument: str       # Round 2 — Gemini defence
    judge_score: float              # Round 3 — GPT-5 final confidence
    model_consensus: float          # = judge_score (feeds ScoreComponents)
    rationale: str                  # Judge's one-sentence rationale
```

`model_consensus` is the Judge's score. `adjudicate.py` does not compute `FindingScore` — that is `confidence.py`'s responsibility.

### 3.4 Failure Handling

| Failure scenario | Fallback |
|---|---|
| Detector fails | Skip ensemble; `model_consensus = 0.5` (neutral), warn stderr |
| Verifier fails (Adversarial succeeds) | Judge proceeds with one-sided debate; noted in rationale |
| Adversarial fails (Verifier succeeds) | Judge proceeds with one-sided debate |
| Both Round 2 fail | Judge skips debate; uses only Detector score |
| Judge fails | `model_consensus = detector_score`; warn stderr |
| All roles fail | `model_consensus = 0.5` (neutral pass-through); findings are never silently dropped — they surface with a neutral score and a `model_confidence_unavailable` label in the comment |

> **Why 0.5 and not 1.0 for failure cases:** Setting `model_consensus = 1.0` on failure would assert maximum model confidence where none exists, causing every LLM-call-failed finding to bypass the confidence gate with full authority. A neutral `0.5` correctly signals "no model assessment available" — the finding still surfaces (because `mode=enforce` suppresses only below `CONFIDENCE_THRESHOLD`, which is `0.70` by default), and the composite score reflects reality.

### 3.5 Caching

Cache key: `sha256(check_id + framework + file_content_hash + control_id)`. Stores full `AdjudicationResult` as JSON. Hit = skip all 4 LLM calls. Opt-out: `AUDIT_CACHE=off`.

### 3.6 Modes

- `off` — skip ensemble entirely; `model_consensus = 1.0` on all findings
- `advisory` — run ensemble, attach scores to comments, suppress nothing
- `enforce` — suppress findings where `FindingScore < CONFIDENCE_THRESHOLD`

---

## Section 4: Confidence Scoring + False Positive Gate (`confidence.py` — new)

**Purpose:** Pure logic module. Computes a composite `FindingScore` from five components, then partitions findings into surfaced vs suppressed.

### 4.1 Composite Scoring Formula

```
FindingScore = w1·RuleConfidence + w2·EvidenceConfidence + w3·ModelConsensus
             + w4·HistoricalPrecision + w5·ControlSeverity + w6·FlowConfidence
```

Default weights (sum to 1.0, configurable via `SCORE_WEIGHTS` env):

| Component | Default weight | Source |
|---|---|---|
| `rule_confidence` | 0.20 | Rule/check metadata |
| `evidence_confidence` | 0.15 | `evidence.py` enrichment quality |
| `model_consensus` | 0.25 | Ensemble provider agreement |
| `historical_precision` | 0.10 | Per-(check_id, framework) precision history |
| `control_severity` | 0.10 | Control's severity level |
| `flow_confidence` | 0.20 | `dataflow.py` source→transform→sink analysis |

All components are normalised to `[0.0, 1.0]` before applying weights.

### 4.2 Component Definitions

**`rule_confidence`** — declared in rule/pack YAML metadata. Semgrep rules carry a `metadata.confidence: HIGH|MEDIUM|LOW` field; pack check entries carry an optional `confidence:` field. Mapping: `HIGH → 0.9`, `MEDIUM → 0.6`, `LOW → 0.3`. Default (no metadata): `0.6`.

**`evidence_confidence`** — computed by `evidence.py` alongside enrichment. Score built additively:
- SARIF code snippet present (always true for findings from all four engines): `+0.4`
- Inline doc comment found (`doc_context != ""`): `+0.3`
- PR body or commit message references the finding's file: `+0.3`
Cap: `min(raw_score, 1.0)`. The three components are designed to saturate at exactly `1.0`; the cap is defensive — adding a future fourth component without reweighting will not silently exceed 1.0.

**When evidence enrichment is skipped** (`fetch_pr_context` fails or `ADJUDICATION_MODE=off`): `evidence_confidence = 0.4` (the SARIF snippet is always present; only the PR-context component is unavailable).

**`model_consensus`** — taken directly from `AdjudicationResult.judge_score`. The sequential debate structure (Detector → Verifier‖Adversarial → Judge) means the Judge already synthesises disagreement between prosecution and defence before producing its final score. No additional averaging or penalty is applied in `confidence.py`. The Judge's score is the consensus.

**`historical_precision`** — per `(check_id, framework)` true-positive rate from past runs. Stored in `.audit-cache/precision.json` as a Beta distribution `(α, β)` (successes, failures). Posterior mean = `α / (α + β)`. No history → `α=4, β=1` (neutral prior of `0.8`).

**Phase 1 write path — `AUDIT_CONFIRM`:** When `AUDIT_CONFIRM` env var is set, `cli.py` parses it as a comma-separated list of `check_id:framework` pairs (e.g. `CKV_AWS_19:gdpr,BC_AWS_199:hipaa`). For each pair, `α` is incremented by 1 in `precision.json` (if the entry doesn't exist, it is created with `α=5, β=1`). The file is written atomically (write temp file → rename) before the confidence gate is applied so the updated precision influences the current run's scores.

**Phase 2 write path:** GitHub "Resolve conversation" webhook updates `β` for dismissed findings (false positive feedback).

**`control_severity`** — maps the control's severity to a score: `critical → 1.0`, `high → 0.8`, `medium → 0.6`, `low → 0.4`. Higher-severity controls receive a boost so they are harder to suppress — a finding touching a `critical` control needs a lower composite score to pass through.

### 4.3 Dataclasses and Interface

`AdjudicationMode` lives in `models.py` alongside `AssessmentStatus`:

```python
class AdjudicationMode(str, Enum):
    OFF = "off"
    ADVISORY = "advisory"
    ENFORCE = "enforce"
```

```python
@dataclass(frozen=True)
class ScoreComponents:
    rule_confidence: float
    evidence_confidence: float
    model_consensus: float
    historical_precision: float
    control_severity: float
    flow_confidence: float      # from dataflow.py; 0.5 if no flow detected

@dataclass(frozen=True)
class ScoredFinding:
    result: AdjudicationResult
    components: ScoreComponents
    finding_score: float        # weighted composite
    surfaced: bool
    suppression_reason: str     # "" if surfaced

def score_finding(
    result: AdjudicationResult,
    components: ScoreComponents,
    weights: dict[str, float],
) -> float: ...

def apply_confidence_gate(
    pairs: list[tuple[AdjudicationResult, ScoreComponents]],  # parallel: each result + its components
    threshold: float,
    mode: AdjudicationMode,
    weights: dict[str, float],
) -> list[ScoredFinding]: ...
```

> **Why `pairs` not `components_map: dict[int, ScoreComponents]`:** Using `id(result)` as a dict key is fragile — CPython can reuse object identities for short-lived objects in list comprehensions. Passing a `list[tuple]` keeps results and their components paired by position, which is both safe and straightforward to zip in `cli.py`.

### 4.4 Gate Logic

- `mode=off` → ensemble skipped (Section 3.6); evidence enrichment and `dataflow.py` still run; `model_consensus` set to `1.0`; composite formula evaluated normally; **no findings suppressed regardless of score**
- `mode=advisory` → full pipeline runs; all findings surfaced; comments show score breakdown
- `mode=enforce` → suppress if `finding_score < threshold`; suppressed findings appear only in the summary table

**Severity gate interaction:** `gate_failed()` in `report.py` is unchanged. Confidence gate is additive: a finding must pass both gates to be surfaced AND block the PR. `gate_failed` operates only on surfaced findings.

### 4.5 PR Comment Format

Scores are formatted as `round(score * 100)` → `{n}%` (integer, no decimal places).

Display label scheme (used consistently in both inline comment and summary formula line):
`rule`, `evidence`, `consensus`, `history`, `severity`, `flow`

```markdown
**[GDPR / Art-32-a — Pseudonymisation and Encryption]**  score: 87%
- Severity: `high`  |  Engine: `checkov` (`CKV_AWS_19`)
- Finding: S3 bucket encryption disabled
- Score breakdown: rule 90% · evidence 80% · consensus 85% · history 78% · severity 80% · flow 90%
Evidence: `encrypted = false`
Rationale: Storing data at rest without encryption violates GDPR Art. 32(a)...
```

**Summary comment** (posted once after inline comments):
```markdown
## Audit Packs Summary
| Framework | Findings | Suppressed | Avg Score |
|---|---|---|---|
| gdpr | 3 | 1 | 84% |
| hipaa | 2 | 0 | 91% |

Total: 5 surfaced, 1 suppressed (FP). Threshold: 70%.
Score = 0.20·rule + 0.15·evidence + 0.25·consensus + 0.10·history + 0.10·severity + 0.20·flow
```

---

## Section 5: Phase 2 Detection Agents (spec only)

### Stub written in Phase 1

`agents.py` defines the abstract base and a no-op implementation:

```python
class DetectionAgent(ABC):
    framework: str

    @abstractmethod
    def detect(self, changed_files: dict[str, str]) -> dict:
        """Return a SARIF dict. Keys: 'engine' set to f'{framework}-agent'."""

class NoOpAgent(DetectionAgent):
    framework = "noop"
    def detect(self, changed_files): return {"runs": []}
```

`cli.py` calls `agent.detect(changed_files)` before `run_checkov()`, merges SARIF, then continues. Phase 2 adds new agent subclasses and registers them; no other module changes.

### Phase 2 agents

| Agent | New detection surface | Why Checkov can't do it |
|---|---|---|
| `DataFlowAgent` | Cross-file source→transform→sink taint analysis; emits `DFA-001` for unprotected sensitive flows | Checkov is resource-level; no intra-code taint tracking |
| `GDPRAgent` | PII variable/field name patterns; missing data-subject-id in DB schemas | Checkov has no PII semantic understanding |
| `HIPAAAgent` | PHI field patterns; IAM wildcards on patient-data resource paths | Checkov doesn't know which resources hold PHI |
| `SOC2Agent` | Missing change-approval PR comments; no audit log on write paths | Governance controls not observable from IaC |
| `FedRAMPAgent` | FIPS-validated cipher list; IL4/IL5 resource tagging | FedRAMP requires specific cipher suites Checkov doesn't enumerate |
| `OrgPolicyAgent` | User rules from `org-policy.yaml` `custom_rules:` block | Org-specific patterns not in any public engine |

Each agent's SARIF uses `engine: "gdpr-agent"` etc. The canonical NIST pack is extended with `(gdpr-agent, <rule-id>) → control` entries so the existing `packs.py` index handles them without modification.

---

## Section 6: GitHub Actions Interface

### 6.1 Cloud usage (default)

```yaml
name: Compliance Review

on:
  pull_request:

jobs:
  compliance:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # required for git diff BASE...HEAD

      - uses: company/audit-packs@v2
        with:
          frameworks: |
            GDPR
            HIPAA
            SOC2

          min-confidence: 0.80

          # Override specific roles; all others use audit-models.yaml defaults
          detector-model: gpt-5
          verifier-model: claude-opus
          judge-model: gpt-5

          fail-on: high

        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GOOGLE_API_KEY: ${{ secrets.GOOGLE_API_KEY }}
```

### 6.1b Air-gapped / local-model usage

For orgs that cannot send code to external APIs. Requires a self-hosted GitHub Actions runner with Ollama (or vLLM) accessible on the network.

```yaml
name: Compliance Review (Air-gapped)

on:
  pull_request:

jobs:
  compliance:
    runs-on: self-hosted          # runner with Ollama on localhost

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: company/audit-packs@v2
        with:
          frameworks: |
            HIPAA
            FedRAMP

          min-confidence: 0.75
          adjudication-mode: enforce
          fail-on: high

          # Point to repo-committed model config; no cloud keys needed
          models-config: .github/audit-models-local.yaml
```

`.github/audit-models-local.yaml` (committed to the repo):

```yaml
models:
  detector:
    provider: ollama
    model: llama3.3:70b
    base_url: http://localhost:11434/v1

  verifier:
    provider: ollama
    model: mistral:7b
    base_url: http://localhost:11434/v1

  adversarial:
    provider: ollama
    model: qwen2.5:32b
    base_url: http://localhost:11434/v1

  judge:
    provider: ollama
    model: llama3.3:70b
    base_url: http://localhost:11434/v1
```

No `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GOOGLE_API_KEY` secrets required. No data leaves the runner.

### 6.2 `action.yml` input definitions

**Migration from current `action.yml`:**

| Input | Status | Change |
|---|---|---|
| `frameworks` | Modified | Format: now accepts both comma-separated and newline-separated (see §6.3). `required: true` (was `default: "nist-800-53"`) |
| `fail-on` | Kept | No change |
| `base-ref` | Kept | No change |
| `scan-mode` | Kept | No change |
| `emit-oscal` | Kept | No change |
| `emit-coverage` | Kept | No change |
| `emit-sarif` | Kept | No change |
| `adjudication-mode` | Modified | Default remains `"off"`; description updated to reflect 4-role ensemble |
| `judge-provider` | Removed | Superseded by per-role model routing (`models-config`, `{role}-model`, `{role}-provider`, `{role}-base-url` env vars) |
| `min-confidence` | New | Composite score threshold (0.0–1.0) |
| `models-config` | New | Path to model routing YAML (cloud or local) |
| `detector-model` | New | Convenience override for detector role model |
| `verifier-model` | New | Convenience override for verifier role model |
| `adversarial-model` | New | Convenience override for adversarial role model |
| `judge-model` | New | Convenience override for judge role model |
| `codeql-sarif` | New | Path to CodeQL SARIF directory (Phase 1) |
| `ast-rules` | New | Path to AST rule scripts directory (Phase 2 — reserved; ignored in Phase 1) |

**Outputs unchanged:** `oscal-path`, `coverage-md-path`, `coverage-html-path`, `sarif-path` are all preserved.

The spec shows only the full desired state of `action.yml` below. Inputs not listed here (`scan-mode`, `emit-oscal`, `emit-coverage`, `emit-sarif`) are carried forward verbatim from the current file.

```yaml
name: "Audit Packs"
description: "Map IaC and code findings to compliance controls with AI-ensemble false-positive elimination."

inputs:
  frameworks:
    description: |
      Newline-separated list of framework IDs to assess.
      Supported: GDPR, HIPAA, SOC2, ISO27001, PCI-DSS, NIST-800-53, FedRAMP, org-policy.
    required: true

  min-confidence:
    description: "Composite score threshold (0.0–1.0). Findings below this are suppressed."
    default: "0.70"

  adjudication-mode:
    description: "off (no LLM calls) | advisory (score shown, nothing suppressed) | enforce (suppress below threshold)"
    default: "enforce"

  fail-on:
    description: "Minimum severity that blocks the PR: low | medium | high | critical"
    default: "high"

  models-config:
    description: |
      Path to a model routing YAML file (relative to repo root).
      Defines provider, model, base_url, and api_key_env for each role
      (detector, verifier, adversarial, judge). Supports cloud APIs and
      local endpoints (Ollama, vLLM, LM Studio, Azure OpenAI).
      If omitted, uses audit-models.yaml at repo root if present,
      otherwise falls back to built-in defaults (cloud models).
    default: "audit-models.yaml"

  # Convenience overrides — take precedence over models-config for rapid iteration
  detector-model:
    description: "Override the detector role's model. Sets DETECTOR_MODEL env."
    default: ""

  verifier-model:
    description: "Override the verifier role's model. Sets VERIFIER_MODEL env."
    default: ""

  adversarial-model:
    description: "Override the adversarial role's model. Sets ADVERSARIAL_MODEL env."
    default: ""

  judge-model:
    description: "Override the judge role's model. Sets JUDGE_MODEL env."
    default: ""

  codeql-sarif:
    description: |
      Path to directory of CodeQL SARIF files produced by github/codeql-action/analyze.
      If absent or empty, CodeQL findings are skipped (graceful degradation).
    default: ""

  ast-rules:
    description: "Path to directory of Tree-sitter AST rule scripts. Defaults to ast-rules/ at repo root."
    default: "ast-rules"

  base-ref:
    description: "Git ref to diff against."
    default: "origin/main"

runs:
  using: "docker"
  image: "Dockerfile"
  env:
    FRAMEWORKS:           ${{ inputs.frameworks }}
    CONFIDENCE_THRESHOLD: ${{ inputs.min-confidence }}
    ADJUDICATION_MODE:    ${{ inputs.adjudication-mode }}
    FAIL_ON:              ${{ inputs.fail-on }}
    AUDIT_MODELS_CONFIG:  ${{ inputs.models-config }}
    DETECTOR_MODEL:       ${{ inputs.detector-model }}
    VERIFIER_MODEL:       ${{ inputs.verifier-model }}
    ADVERSARIAL_MODEL:    ${{ inputs.adversarial-model }}
    JUDGE_MODEL:          ${{ inputs.judge-model }}
    BASE_REF:             ${{ inputs.base-ref }}
    CODEQL_SARIF_DIR:     ${{ inputs.codeql-sarif }}
    AST_RULES_DIR:        ${{ inputs.ast-rules }}
    GITHUB_TOKEN:         ${{ github.token }}
    PR_NUMBER:            ${{ github.event.pull_request.number }}
```

Empty string env vars are ignored by `cli.py` model routing — only non-empty values override the YAML file config.

### 6.3 Framework name normalisation

`cli.py` normalises framework names from the `FRAMEWORKS` env by stripping whitespace, lowercasing, and mapping aliases to pack IDs. **The parser accepts both comma-separated and newline-separated formats** (e.g. `"GDPR,HIPAA"` and a multiline block scalar both work), enabling backward compatibility with existing `frameworks: "nist-800-53"` usage.

| User input | Pack ID |
|---|---|
| `GDPR`, `gdpr` | `gdpr` |
| `HIPAA`, `hipaa` | `hipaa` |
| `SOC2`, `soc2`, `soc-2` | `soc2` |
| `ISO27001`, `iso27001`, `iso-27001` | `iso27001` |
| `PCI-DSS`, `pcidss`, `pci_dss` | `pci-dss` |
| `NIST-800-53`, `nist800-53`, `nist` | `nist-800-53` |
| `FedRAMP`, `fedramp` | `fedramp` |
| `org-policy`, `org_policy`, `internal` | `org-policy` |

Unknown names raise a clear error at startup (not at reporting time).

---

## New and changed files

### Phase 1 deliverables

| File | Status | Change |
|---|---|---|
| `src/audit_packs/dataflow.py` | New | `DataFlow`, `extract_data_flows`, `flow_confidence` |
| `src/audit_packs/models.py` | Extended | `PathNode` dataclass; `doc_context` + `evidence_path` fields on `Finding`; `AdjudicationMode` enum |
| `src/audit_packs/evidence.py` | New | `PRContext`, `fetch_pr_context`, `extract_doc_context`, `enrich` |
| `src/audit_packs/confidence.py` | New | `ScoreComponents`, `ScoredFinding`, `score_finding`, `apply_confidence_gate` |
| `src/audit_packs/agents.py` | New | `DetectionAgent` ABC + `NoOpAgent` (Phase 2 adds `DataFlowAgent` and framework agents) |
| `src/audit_packs/adjudicate.py` | Extended | 4-role sequential debate pipeline; model routing; `evidence_path` formatted in prompts |
| `src/audit_packs/engines.py` | Extended | `read_codeql_sarif()` (CodeQL SARIF directory reader) |
| `src/audit_packs/normalize.py` | Extended | `codeFlows` → `PathNode` tuple extraction |
| `audit-models.yaml` | New | Default model routing config |
| `tests/test_codeql_normalize.py` | New | Unit test: SARIF with codeFlows → Finding with evidence_path |
| `src/audit_packs/report.py` | Extended | Confidence badge in comments, summary table |
| `src/audit_packs/cli.py` | Extended | Wire `evidence.py`, `agents.py`, `confidence.py` |
| `rules/pii-fields.yaml` | New | Semgrep rule: PII variable name patterns |
| `rules/insecure-config.yaml` | New | Semgrep rule: insecure config flags |
| `tests/test_dataflow.py` | New | Unit tests for flow extraction, `flow_confidence` scoring, all four return values |
| `tests/test_evidence.py` | New | Unit tests for enrichment logic + evidence_confidence scoring |
| `tests/test_confidence.py` | New | Unit tests for composite formula, all six components, gate logic |
| `tests/test_agents.py` | New | Unit test for NoOpAgent |
| `tests/test_cli_frameworks.py` | New | Unit tests for framework name normalisation (all aliases, unknown name error) |
| `.audit-cache/precision.json` | Runtime artifact | Beta distribution store for historical precision; gitignored |
| `action.yml` | Extended | New inputs: `frameworks`, `min-confidence`, `adjudication-mode`, per-role model inputs |

### Unchanged
`diff.py`, `packs.py`, `coverage.py`, `oscal.py`, all pack YAML files.

(`normalize.py` and `engines.py` are both **Extended** — see Phase 1 deliverables table above.)

---

## Testing approach

- **Unit (pure modules):** `evidence.py` (extract_doc_context, enrich), `confidence.py` (gate logic, all three modes), `agents.py` (NoOpAgent returns empty SARIF). No mocking of LLMs needed.
- **Adjudicate unit:** Mock each role's HTTP call independently; assert sequential execution order (Detector → Round 2 parallel → Judge), cache hit skips all 4 calls, each failure scenario in the failure table produces the correct fallback `model_consensus`.
- **Integration:** Existing `test_integration.py` extended — run with `ADJUDICATION_MODE=off` so LLMs not required in CI. One new `test_integration_advisory.py` with mocked providers asserts confidence badges appear in comment bodies.
- **Framework normalisation:** `test_cli_frameworks.py` — all alias inputs resolve to correct pack IDs; unknown name raises `ValueError` with clear message at startup.
- **Regression:** Full `pytest -v` must pass with no LLM keys configured (`ADJUDICATION_MODE=off` default in CI).

---

## Environment variables (Phase 1 additions)

| Variable | Default | Purpose |
|---|---|---|
| `ADJUDICATION_MODE` | `off` | `off` / `advisory` / `enforce` |
| `CONFIDENCE_THRESHOLD` | `0.7` | Suppress findings below composite score |
| `AUDIT_MODELS_CONFIG` | `audit-models.yaml` | Path to model routing YAML (cloud or local) |
| `DETECTOR_MODEL` | — | Override detector model (takes precedence over YAML) |
| `DETECTOR_PROVIDER` | — | Override detector provider |
| `DETECTOR_BASE_URL` | — | Override detector endpoint (local/self-hosted) |
| `VERIFIER_MODEL` | — | Override verifier model |
| `VERIFIER_PROVIDER` | — | Override verifier provider |
| `VERIFIER_BASE_URL` | — | Override verifier endpoint |
| `ADVERSARIAL_MODEL` | — | Override adversarial model |
| `ADVERSARIAL_PROVIDER` | — | Override adversarial provider |
| `ADVERSARIAL_BASE_URL` | — | Override adversarial endpoint |
| `JUDGE_MODEL` | — | Override judge model |
| `JUDGE_PROVIDER` | — | Override judge provider |
| `JUDGE_BASE_URL` | — | Override judge endpoint |
| `OPENAI_API_KEY` | — | Required for `provider: openai`; omit for local providers |
| `ANTHROPIC_API_KEY` | — | Required for `provider: anthropic` |
| `GOOGLE_API_KEY` | — | Required for `provider: google` |
| `AUDIT_CACHE` | `on` | Set `off` to disable finding cache |
| `SCORE_WEIGHTS` | `rule:0.20,evidence:0.15,consensus:0.25,history:0.10,severity:0.10,flow:0.20` | Composite score component weights. All 6 keys required. Weights must sum to 1.0 ± 0.001 or `ValueError` at startup. Partial specs are not accepted — specify all 6 or omit the var entirely. |
| `AUDIT_CONFIRM` | — | Comma-separated `check_id:framework` pairs (e.g. `CKV_AWS_19:gdpr,BC_AWS_199:hipaa`) to mark as confirmed TPs, incrementing `α` in `precision.json` |
| `CODEQL_SARIF_DIR` | — | Path to directory of CodeQL SARIF files (maps to `codeql-sarif` action input) |
| `AST_RULES_DIR` | `ast-rules` | Path to Tree-sitter AST rule scripts directory (Phase 2 — reserved; ignored in Phase 1) |

---

## Deferred / out of scope

- API schema scanning (OpenAPI/Swagger) — deferred to a future spec
- Phase 2 framework-specific agent implementations — separate spec per agent
- Multi-tenant pack distribution / pack versioning — future
- Real-time streaming of confidence scores to GitHub Checks UI — future
