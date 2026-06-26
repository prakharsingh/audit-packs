# Architectural Alignment — Design Spec

**Date:** 2026-06-26
**Scope:** Full architectural alignment — monorepo package split (5 independent installable packages), pack schema v2 with per-framework directories and `evidence_requirements`, AI terminology rename, and README repositioning.

---

## Background

The existing codebase is a single flat Python package (`src/audit_packs/`) containing 14 modules and ~3,500 lines. The architecture review confirms the technical direction is sound and identifies the following gaps:

- All modules share one install unit; no isolation between pure-Python logic and IO-bound modules
- Pack files are flat YAML crosswalks with no `evidence_requirements` or `supported_scanners` metadata
- AI ensemble uses "adversarial/judge/debate" terminology that undermines enterprise trust
- README positions the project as a compliance mapper rather than a Compliance Intelligence Engine
- No explicit scanner support table or scanner-agnostic positioning

This spec closes all five gaps in a single big-bang migration.

---

## Architectural Principle

```
Scanner Output (SARIF)
        │
        ▼
audit-packs-core      (normalize, diff, dataflow — pure Python)
        │
        ▼
audit-packs-mapping   (packs, coverage, oscal — pure Python)
        │
        ▼
audit-packs-evidence  (evidence enrichment, detection agents — optional GitHub API)
        │
        ▼
audit-packs-ai        (AI verification, confidence scoring — optional LLM deps)
        │
        ▼
audit-packs-action    (engines, report, CLI — GitHub Action orchestrator)
        │
        ▼
Outputs: inline PR comments / OSCAL / SARIF / coverage HTML
```

No downstream package knows which scanner produced a finding. The GitHub Action is one interface to the engine; CLI, REST API, and CI adapters are future interfaces to the same packages.

---

## Section 1: Package Structure & Boundaries

### Directory layout

```
packages/
  core/
    src/audit_packs_core/
      models.py        # Finding, ControlFinding, ControlStatus, AdjudicationResult, enums
      diff.py          # parse_unified_diff()
      normalize.py     # sarif_to_findings(), extract_rule_confidences()
      dataflow.py      # extract_data_flows(), flow_confidence()
    pyproject.toml
    tests/             # (empty — root tests/ covers core)

  mapping/
    src/audit_packs_mapping/
      packs.py         # load_pack(), map_findings()
      coverage.py      # compute_coverage()
      oscal.py         # to_assessment_results()
    pyproject.toml

  evidence/
    src/audit_packs_evidence/
      evidence.py      # enrich(), fetch_pr_context(), extract_doc_context()
      agents.py        # DetectionAgent ABC + GDPRAgent, HIPAAAgent, SOC2Agent, etc.
    pyproject.toml

  ai/
    src/audit_packs_ai/
      adjudicate.py    # AI verification ensemble
      confidence.py    # ScoreComponents, score_finding(), apply_confidence_gate()
    pyproject.toml

  action/
    src/audit_packs_action/
      engines.py       # CheckovEngine, SemgrepEngine, CodeQLEngine, ASTEngine
      report.py        # build_comments(), post_review(), build_sarif(), write_job_summary()
      cli.py           # analyze(), assess(), main()
    pyproject.toml
```

### Dependency graph

```
audit-packs-core  ◄─── audit-packs-mapping  ◄─┐
audit-packs-core  ◄─── audit-packs-evidence ◄─┤
audit-packs-core  ◄─┐                          │
audit-packs-mapping ◄┤── audit-packs-ai    ◄───┤
audit-packs-evidence◄┘                         │
                       audit-packs-action ──────┘
                         (depends on all 4 above)
```

No cycles. `core` has no upstream dependencies. `action` depends on everything.

### Per-package `pyproject.toml` dependencies

| Package | `dependencies` |
|---------|----------------|
| `audit-packs-core` | `pyyaml` only |
| `audit-packs-mapping` | `audit-packs-core` |
| `audit-packs-evidence` | `audit-packs-core`; optional: `httpx` |
| `audit-packs-ai` | `audit-packs-core`, `audit-packs-mapping`, `audit-packs-evidence`; optional: `openai`, `anthropic`, `google-generativeai` |
| `audit-packs-action` | all 4 above; `checkov`, `semgrep` |

### IO boundary rule (preserved)

Only `evidence.py`, `engines.py`, `report.py`, and `adjudicate.py` make network or subprocess calls. These modules now live in two packages (`evidence` and `action`), making the boundary structurally explicit.

### Import changes

All internal imports updated to new package names:

```python
# before
from audit_packs.models import Finding

# after
from audit_packs_core.models import Finding
```

No compatibility shims. The old `src/audit_packs/` directory is deleted.

---

## Section 2: Pack Schema v2 & Directory Restructure

### Directory layout

```
packs/
  nist-800-53/
    controls.yaml      # canonical pack
  soc2/
    controls.yaml
  gdpr/
    controls.yaml
  hipaa/
    controls.yaml
  iso27001/
    controls.yaml
  pci-dss/
    controls.yaml
  fedramp/
    controls.yaml
  org-policy/
    controls.yaml
```

### Schema v2

```yaml
schema_version: "2"
framework: gdpr
crosswalk: nist-800-53          # omit for canonical pack

controls:
  - id: gdpr-art-32
    title: "Security of Processing"
    severity: high
    references:
      - "GDPR Article 32"
    supported_scanners:
      - checkov
      - semgrep
    maps_to: SC-13               # present only in crosswalk packs
    mappings:
      - engine: checkov
        check_id: CKV_AWS_19
      - engine: semgrep
        check_id: audit-packs.weak-cipher
    evidence_requirements:
      - type: code_snippet
        description: "Encryption algorithm used at the affected resource"
      - type: resource_name
        description: "Name of the unencrypted resource"
```

**New fields vs schema v1:**

| Field | Description |
|-------|-------------|
| `schema_version: "2"` | Required on all packs; v1 files have no version field |
| `supported_scanners` | Per-control list of scanner IDs that can detect this control |
| `evidence_requirements` | Declarative evidence types the output layer should collect |

### `packs.py` changes

- `load_pack(framework)` discovers `packs/<framework>/controls.yaml` instead of `packs/<framework>.yaml`
- `map_findings()` attaches `evidence_requirements` from matched controls to returned `ControlFinding`

### `models.py` change

`ControlFinding` gains one new field:

```python
@dataclass(frozen=True)
class ControlFinding:
    finding: Finding
    framework: str
    control_id: str
    control_title: str
    evidence_requirements: tuple[dict, ...] = ()   # NEW
```

### Migration script

`scripts/migrate_packs_v2.py` — reads each `packs/<framework>.yaml` (v1 flat file), emits `packs/<framework>/controls.yaml` (v2 schema). Run once during migration; v1 flat files are deleted in the same commit.

---

## Section 3: Terminology Rename

### `models.py` — `AdjudicationResult` fields

| Before | After |
|--------|-------|
| `adversarial_argument: str` | `challenger_argument: str` |
| `judge_score: float` | `consensus_score: float` |

### `adjudicate.py` — roles and internal names

| Before | After |
|--------|-------|
| `"adversarial"` (model config key) | `"challenger"` |
| `"judge"` (model config key) | `"consensus"` |
| `_run_adversarial()` | `_run_challenger()` |
| `adversarial_argument=` (all sites) | `challenger_argument=` |
| `judge_score=` (all sites) | `consensus_score=` |
| `"adversarial_argument"` (cache JSON key) | `"challenger_argument"` |
| `"judge_score"` (cache JSON key) | `"consensus_score"` |

### `audit-models.yaml` — role keys

```yaml
# after (flat top-level keys, same structure as before)
detector:
  provider: anthropic
  model: claude-sonnet-4-6
verifier:
  provider: anthropic
  model: claude-sonnet-4-6
challenger:
  provider: anthropic
  model: claude-sonnet-4-6
consensus:
  provider: openai
  model: gpt-4o
```

### Cache migration

`adjudicate.py` cache loader remaps old JSON keys on read: if a cached entry contains `adversarial_argument`, it is transparently renamed to `challenger_argument` before use. No cache wipe required.

---

## Section 4: README Repositioning

### Tagline

**Before:**
> Map IaC security findings to compliance framework controls and post evidence-backed, control-tagged inline PR review comments with a configurable severity gate.

**After:**
> An evidence-first Compliance Intelligence Engine that transforms security scanner findings into standardized, evidence-backed compliance artifacts — inline PR comments, OSCAL, SARIF, and coverage reports.

### Opening paragraph

**Before:**
> Detection is delegated entirely to best-in-class OSS engines (Checkov, Semgrep, optionally CodeQL). What this action adds is the **control mapping + evidence + PR UX layer**...

**After:**
> Detection is delegated entirely to best-in-class OSS engines (Checkov, Semgrep, CodeQL, and future scanners). The core engine is scanner-agnostic: any tool that emits SARIF can feed it. What audit-packs adds is the **normalization → compliance mapping → evidence generation → output** layer...

### Scanner support table (new addition)

| Scanner | Status |
|---------|--------|
| Checkov | Supported |
| Semgrep | Supported |
| CodeQL | Supported (SARIF dir input) |
| Trivy | Planned |
| tfsec | Planned |
| gitleaks | Planned |

No other README sections change (architecture diagram, env var table, usage examples unchanged).

---

## Section 5: Monorepo Tooling & Migration

### Workspace manager

`uv` workspaces. Root `pyproject.toml` becomes a workspace manifest only.

```toml
[tool.uv.workspace]
members = [
  "packages/core",
  "packages/mapping",
  "packages/evidence",
  "packages/ai",
  "packages/action",
]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = [
  "packages/core/src",
  "packages/mapping/src",
  "packages/evidence/src",
  "packages/ai/src",
  "packages/action/src",
]
```

### Test structure

Tests remain in the root `tests/` directory. Each test file is updated in-place to import from new package names. No new test files are added as part of this spec.

### Dockerfile

```dockerfile
# before
RUN pip install -e ".[dev]"

# after
RUN pip install \
    -e packages/core \
    -e packages/mapping \
    -e packages/evidence \
    -e "packages/ai[ai]" \
    -e packages/action
```

### What does NOT change

- `rules/` Semgrep YAML files
- `.agent/` brain directory
- All env var names and `action.yml` inputs
- GitHub Action public interface (inputs, outputs, `runs:` block)
- `CLAUDE.md` module descriptions (updated separately post-migration)

---

## Execution Order (big-bang)

1. Write `scripts/migrate_packs_v2.py` and run it — produces v2 pack files
2. Create `packages/` directory tree and move/update each module
3. Update all internal imports across all modules and tests
4. Update `pyproject.toml` (workspace manifest + per-package configs)
5. Rename terminology in `models.py`, `adjudicate.py`, `audit-models.yaml`, all tests
6. Update README tagline, opening paragraph, add scanner table
7. Delete `src/audit_packs/`, delete v1 pack flat files
8. Update `Dockerfile`
9. Run `pytest -v` — must pass with zero failures

---

## Success Criteria

- `pytest -v` passes with zero failures after migration
- `pip install packages/core` works with zero external deps
- `pip install packages/mapping` pulls in `core` transitively
- `from audit_packs_core.models import Finding` works
- `packs/gdpr/controls.yaml` loads without error; `evidence_requirements` is accessible on matched `ControlFinding`
- No references to `adversarial_argument` or `judge_score` remain in source or tests
- Docker build succeeds and smoke test passes
