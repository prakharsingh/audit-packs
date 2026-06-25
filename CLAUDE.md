# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## What this project is

**audit-packs** is an open-source GitHub Action that maps IaC security findings to compliance framework controls and posts evidence-backed inline PR review comments with a severity gate.

A Python orchestrator (`cli.py`) delegates detection to OSS engines (Checkov, Semgrep, optionally CodeQL) and framework-specific detection agents, normalises SARIF output to a common `Finding` model, enriches findings with evidence and data-flow context, optionally adjudicates them through an AI ensemble, confidence-gates low-quality findings, maps survivors to compliance controls via YAML packs, and posts control-tagged PR review comments. The project differentiates on **control-mapping + evidence UX + AI adjudication**, not on building new analysis engines.

Frameworks: NIST 800-53, SOC 2, GDPR, HIPAA, ISO 27001, PCI-DSS, FedRAMP, org-policy.

---

## Key design rules

- **Never re-implement detection logic.** Engines (Checkov, Semgrep, CodeQL) are invoked as subprocesses; findings come back as SARIF. `ASTEngine` is the sole intentional exception: it runs Python AST visitors in-process for patterns not expressible in Semgrep YAML (e.g. taint flows that require multi-node AST traversal). Do not add further in-process analysis engines; extend `rules/*.yaml` for new Semgrep patterns instead.
- **Packs are data, not code.** A framework pack = YAML mapping `(engine, check_id) → control`. NIST 800-53 is the canonical pack; all other frameworks are crosswalk packs that reference it via `crosswalk: nist-800-53` and `maps_to:` entries.
- **Diff-filtered only (diff path).** Only findings on lines added/changed in the PR are reported in inline comments and the severity gate.
- **SARIF is the lingua franca.** All engines and agents emit SARIF; `normalize.py` converts it to `Finding` dataclasses before anything else touches the output.
- **Detection agents also emit SARIF.** `agents.py` framework agents (`GDPRAgent`, `HIPAAAgent`, etc.) implement the same `DetectionAgent.detect() → SARIF dict` contract.
- Severity vocabulary is exactly: `low`, `medium`, `high`, `critical`.
- License: Apache-2.0. No paid-tier engine features (Semgrep Pro, Bearer Pro) may be required.
- Network/subprocess IO is confined to four modules: `engines.py` (subprocesses + `git diff`), `evidence.py` (GitHub PR context API), `adjudicate.py` (LLM provider APIs), and `report.py` (GitHub review API). Everything else — `normalize`, `diff`, `packs`, `dataflow`, `confidence`, `coverage`, `oscal` — is pure Python, testable without network or installed tools.

---

## Development commands

```bash
# Install in editable mode (venv already at .venv; engines on .venv/bin PATH)
pip install -e ".[dev]"

# Run all tests (pythonpath=["src"] is set in pyproject.toml — no install required)
pytest -v

# Run a single test file
pytest tests/test_packs.py -v

# Run a single test
pytest tests/test_packs.py::test_map_findings_crosswalk_soc2 -v

# Build the Docker action image
docker build -t audit-packs:dev .

# Run the Docker smoke test
pytest tests/test_docker_smoke.py -v
# or directly: ./tests/docker_smoke.sh

# Smoke-check engines (available in .venv/bin)
checkov --version
semgrep --version
```

---

## Code structure

```
src/audit_packs/
  models.py      # Finding, ControlFinding, ControlStatus, AdjudicationResult (frozen dataclasses);
                 # AssessmentStatus / AdjudicationMode enums; SEVERITIES, severity_rank()
  diff.py        # parse_unified_diff() → {file: set[line]}
  normalize.py   # sarif_to_findings(); extract_rule_confidences()
  engines.py     # BaseEngine → CheckovEngine / SemgrepEngine / CodeQLEngine (async run_scan_async,
                 # sync fallback); run_checkov / run_semgrep / run_git_diff / read_codeql_sarif
  agents.py      # DetectionAgent ABC + per-framework agents (GDPRAgent, HIPAAAgent, SOC2Agent,
                 # FedRAMPAgent, OrgPolicyAgent, DataFlowAgent); build_agents() → list[DetectionAgent]
  packs.py       # load_pack(), map_findings() — control mapping + NIST crosswalk resolution
  evidence.py    # enrich(), fetch_pr_context() [GitHub IO], evidence_confidence(),
                 # extract_doc_context()
  dataflow.py    # extract_data_flows() (python/hcl/yaml), flow_confidence()
  adjudicate.py  # AI ensemble (detector → verifier → adversarial → judge) [LLM HTTP IO];
                 # load_model_config(); result caching in .audit-cache/
  confidence.py  # ScoreComponents, score_finding(), apply_confidence_gate(), DEFAULT_WEIGHTS,
                 # historical precision helpers (get/update)
  coverage.py    # compute_coverage() → list[ControlStatus] (one per framework control)
  oscal.py       # to_assessment_results() — NIST OSCAL assessment-results JSON
  report.py      # build_comments(), build_summary_comment(), gate_failed(),
                 # build_coverage_matrix(md/html), build_sarif(), post_review() [GitHub IO],
                 # write_job_summary()
  cli.py         # analyze() (diff path) + assess() (full path) + main() — env-driven orchestration

packs/
  nist-800-53.yaml          # canonical: (engine, check_id) → control
  soc2|gdpr|hipaa|iso27001|pci-dss|fedramp|org-policy.yaml   # crosswalk → nist-800-53

rules/
  weak-cipher.yaml / no-tls-verify.yaml / pii-fields.yaml /
  insecure-config.yaml / hardcoded-credential.yaml /
  overpermissive-iam.yaml / missing-audit-log.yaml
  # Authored Semgrep rules — extend detection beyond Checkov check IDs
```

---

## How the pipeline runs

`cli.main()` reads configuration from environment variables (mapped from `action.yml` inputs) and runs one or both scan paths controlled by `SCAN_MODE`:

**diff path — `analyze()`**
engines + agents → `sarif_to_findings` → `enrich` (evidence + doc_context) → `extract_data_flows` → diff-filter to PR-changed lines → `map_findings` (control mapping) → `adjudicate` (AI ensemble, if enabled) → `apply_confidence_gate` → `ScoredFinding[]` → `build_comments` + `post_review` + `gate_failed`. Returns exit code 1 if the severity gate trips.

**full path — `assess()`**
engines + agents over whole workspace → enrich → `map_findings` → (optional adjudication) → `compute_coverage` → `ControlStatus[]` → emits `oscal.json`, `coverage.md`/`.html`, `audit-packs.sarif`, and GitHub job summary.

**Confidence model** (`confidence.py` `DEFAULT_WEIGHTS`): composite of six signals:

| Signal | Weight |
|--------|--------|
| rule confidence (from SARIF) | 0.20 |
| evidence confidence | 0.15 |
| model consensus (AI ensemble) | 0.25 |
| historical precision | 0.10 |
| control severity | 0.10 |
| data-flow confidence | 0.20 |

`CONFIDENCE_THRESHOLD` (default 0.70) suppresses low-confidence findings when `ADJUDICATION_MODE=enforce`. Historical precision persists in `.audit-cache/precision.json`; `AUDIT_CONFIRM=check:framework,...` records confirmed true positives.

**AI routing** (`audit-models.yaml`): maps each role (`detector` / `verifier` / `adversarial` / `judge`) to `provider / model / base_url / api_key_env`. Per-role overrides via `DETECTOR_MODEL`, `VERIFIER_MODEL`, `ADVERSARIAL_MODEL`, `JUDGE_MODEL` env vars. `ADJUDICATION_MODE=off` makes zero LLM calls.

**Key env vars** (all have defaults; see `action.yml` for the full list):

| Env | Purpose | Default |
|-----|---------|---------|
| `FRAMEWORKS` | comma/newline framework IDs | required |
| `SCAN_MODE` | `diff` \| `full` \| `both` | `both` |
| `FAIL_ON` | gate severity `low`…`critical` | `high` |
| `ADJUDICATION_MODE` | `off` \| `advisory` \| `enforce` | `off` |
| `CONFIDENCE_THRESHOLD` | composite score cutoff | `0.70` |
| `AUDIT_MODELS_CONFIG` | model routing YAML path | `audit-models.yaml` |
| `CODEQL_SARIF_DIR` | dir of CodeQL SARIF (optional) | `` |
| `EMIT_OSCAL` / `EMIT_COVERAGE` / `EMIT_SARIF` | toggle full-path outputs | `true` |

---

## Agentic-stack brain (`.agent/`)

This repo uses the portable agentic-stack brain. Read at session start (in order):

1. `.agent/AGENTS.md` — full map of the brain
2. `.agent/memory/personal/PREFERENCES.md` — how this user works
3. `.agent/memory/working/REVIEW_QUEUE.md` — pending lessons to review
4. `.agent/memory/semantic/LESSONS.md` — distilled patterns

### Recall before non-trivial actions

For any task involving deploy, migration, schema change, failing test, debug, or refactor:

```bash
python3 .agent/tools/recall.py "<one-line description>"
```

Show output in a `Consulted lessons before acting:` block. If a surfaced lesson conflicts with your intended action, stop and explain why.

### Memory tools

```bash
python3 .agent/tools/show.py               # brain state overview
python3 .agent/tools/learn.py "<rule>" --rationale "<why>"   # teach a new rule
python3 .agent/tools/memory_reflect.py <skill> <action> <outcome> --importance N
```

Log manually after: completing a major feature, any rollback/incident, any architectural decision, any non-obvious project constraint.

### Skills

Read `.agent/skills/_index.md` for discovery. Load a full `SKILL.md` only when its triggers match the current task.

### Hard constraints

- Never force push to `main`, `production`, or `staging`.
- Never delete episodic or semantic memory entries — archive them.
- Never modify `.agent/protocols/permissions.md`.
- Never hand-edit `.agent/memory/semantic/LESSONS.md` — use `graduate.py`.
- Installing new dependencies or modifying CI/CD requires approval (see `.agent/protocols/permissions.md`).
