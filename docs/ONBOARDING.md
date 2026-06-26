# Contributing to audit-packs

Welcome. This guide takes you from zero to a running test suite and a clear mental model of how the project works. It is written for engineers who have not seen the codebase before.

---

## Table of contents

1. [What this project does](#1-what-this-project-does)
2. [Prerequisites](#2-prerequisites)
3. [Local setup](#3-local-setup)
4. [Running the tests](#4-running-the-tests)
5. [How the pipeline works](#5-how-the-pipeline-works)
6. [Codebase map](#6-codebase-map)
7. [Adding a new framework pack](#7-adding-a-new-framework-pack)
8. [Running the action locally](#8-running-the-action-locally)
9. [Key design rules](#9-key-design-rules)

---

## 1. What this project does

**audit-packs** is an open-source GitHub Action that connects IaC security scanners to compliance frameworks. When a pull request is opened, it:

1. Runs Checkov, Semgrep, and optionally CodeQL against the changed files.
2. Normalises every scanner's output into a common `Finding` model (SARIF is the exchange format).
3. Filters findings to only the lines that changed in the PR.
4. Maps each surviving finding to a compliance control (e.g. `CKV_AWS_19` → NIST SC-13 "Cryptographic Protection").
5. Optionally adjudicates findings through a multi-model AI ensemble to reduce false positives.
6. Posts inline PR review comments that name the failing control, not just the scanner rule.
7. Exits with code 1 if any finding meets or exceeds the configured severity gate.

In full-scan mode it also emits an OSCAL `assessment-results` JSON, a Markdown/HTML coverage matrix, and an aggregate SARIF file for GitHub code scanning.

The project differentiates on **control mapping + evidence UX + AI adjudication**, not on building new detection logic. Checkov and Semgrep do the detection; audit-packs makes the output compliance-legible.

Supported frameworks: NIST 800-53, SOC 2, GDPR, HIPAA, ISO 27001, PCI-DSS, FedRAMP, org-policy.

---

## 2. Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11+ | `python3 --version` to check |
| git | any recent | needed by the diff path at test time |
| Docker | any recent | only needed to build/run the action image |

You do not need Checkov or Semgrep installed globally. The dev install (step 3) puts them on the `.venv/bin` PATH.

---

## 3. Local setup

```bash
# Clone and enter the repo
git clone https://github.com/prakharsingh/audit-packs.git
cd audit-packs

# Create a virtual environment (Python 3.11+)
python3 -m venv .venv
source .venv/bin/activate

# Install the package and all dev dependencies
# This also installs checkov and semgrep into .venv/bin
pip install -e ".[dev]"

# Verify the engines are on PATH
checkov --version
semgrep --version

# Verify the CLI entry point works
audit-packs --help
```

After this, `.venv/bin/audit-packs` is the CLI entry point (mapped from `audit_packs_action.cli:main` in `packages/action/pyproject.toml`).

---

## 4. Running the tests

```bash
# Run the full suite
pytest -v

# Run a single test module
pytest tests/test_packs.py -v

# Run a single test
pytest tests/test_packs.py::test_map_findings_crosswalk_soc2 -v
```

`pyproject.toml` sets `pythonpath` to the five `packages/*/src` directories, so you do not need to install the packages before running tests — `pytest` resolves imports directly from the source trees.

### Test layout

Each source module has a corresponding test file. The majority of tests are pure-Python and run without network access or installed tools:

| Test file | What it covers |
|---|---|
| `test_packs.py` | Pack loading, NIST mapping, crosswalk resolution |
| `test_normalize.py` | SARIF-to-Finding conversion |
| `test_diff.py` | Unified-diff line-map parsing |
| `test_confidence.py` | Score calculation and gate logic |
| `test_coverage.py` | Control coverage rollup |
| `test_agents.py` | Framework detection agent SARIF output |
| `test_adjudicate.py` | AI ensemble (mocked LLM calls) |
| `test_evidence.py` | Evidence enrichment (mocked GitHub API) |
| `test_report.py` | Comment and SARIF output formatting |
| `test_integration.py` | End-to-end pipeline (no network) |

Test fixtures live in `tests/fixtures/`: a sample Checkov SARIF in `sarif/` and a small Terraform file in `terraform/`.

---

## 5. How the pipeline works

`cli.main()` reads configuration from environment variables (see `action.yml` for the full list) and dispatches to one or both of:

### diff path — `analyze()`

Used during PR runs. Only findings on lines changed in the PR are reported.

```
engines + agents
    → sarif_to_findings()       [normalize.py]
    → enrich()                  [evidence.py — GitHub PR context + doc strings]
    → extract_data_flows()      [dataflow.py]
    → diff-filter               [diff.py — keep only PR-changed lines]
    → map_findings()            [packs.py — (engine, check_id) → control]
    → adjudicate()              [adjudicate.py — AI ensemble, if enabled]
    → apply_confidence_gate()   [confidence.py]
    → build_comments()          [report.py]
    → post_review()             [report.py — GitHub API]
    → gate_failed()             [report.py — exit 1 if gate trips]
```

### full path — `assess()`

Used for scheduled compliance posture snapshots. Scans the whole workspace.

```
engines + agents (all files)
    → sarif_to_findings()
    → enrich()
    → map_findings()
    → adjudicate()              [optional]
    → compute_coverage()        [coverage.py — one ControlStatus per control]
    → to_assessment_results()   [oscal.py]
    → build_coverage_matrix()   [report.py]
    → write artifacts: oscal.json, coverage.md, coverage.html, audit-packs.sarif
```

### Confidence model

Every finding is scored on six signals before the gate is applied:

| Signal | Weight |
|---|---|
| Rule confidence (from SARIF) | 0.20 |
| Data-flow confidence | 0.20 |
| Model consensus (AI ensemble) | 0.25 |
| Evidence confidence | 0.15 |
| Control severity | 0.10 |
| Historical precision | 0.10 |

The default threshold is 0.70. Findings below it are suppressed when `ADJUDICATION_MODE=enforce`. Historical precision is tracked per engine+check_id in `.audit-cache/precision.json`.

### AI adjudication (optional)

When `ADJUDICATION_MODE` is `advisory` or `enforce`, each finding passes through a four-role ensemble:

```
detector → verifier → challenger → consensus
```

Each role is independently routed to a provider and model via `audit-models.yaml`. The default routing is:

| Role | Provider | Model |
|---|---|---|
| detector | OpenAI | gpt-4o |
| verifier | Anthropic | claude-opus-4-5 |
| challenger | Google | gemini-1.5-pro |
| consensus | OpenAI | gpt-4o |

Override any role with `DETECTOR_MODEL`, `VERIFIER_MODEL`, `CHALLENGER_MODEL`, or `CONSENSUS_MODEL` env vars. See `examples/audit-models/` for provider-specific configurations including local Ollama.

Set `ADJUDICATION_MODE=off` to make zero LLM calls. This is the default.

---

## 6. Codebase map

```
packages/
  core/src/audit_packs_core/
    models.py       Finding, ControlFinding, ControlStatus, AdjudicationResult,
                    ScoredFinding (frozen dataclasses); enums; SEVERITIES
    diff.py         parse_unified_diff() → {file: set[line]}
    normalize.py    sarif_to_findings(); extract_rule_confidences()
    dataflow.py     extract_data_flows() (Python/HCL/YAML); flow_confidence()

  mapping/src/audit_packs_mapping/
    packs.py        load_pack(); map_findings(); iter_controls()
    coverage.py     compute_coverage() → list[ControlStatus]
    oscal.py        to_assessment_results() — NIST OSCAL assessment-results JSON

  evidence/src/audit_packs_evidence/
    evidence.py     enrich(); fetch_pr_context() [GitHub IO];
                    evidence_confidence(); extract_doc_context()
    agents.py       DetectionAgent ABC + GDPRAgent, HIPAAAgent, SOC2Agent,
                    FedRAMPAgent, OrgPolicyAgent, DataFlowAgent;
                    build_agents() → list[DetectionAgent]

  ai/src/audit_packs_ai/
    adjudicate.py   AI ensemble [LLM HTTP IO]; load_model_config();
                    result caching in .audit-cache/
    confidence.py   ScoreComponents; score_finding(); apply_confidence_gate();
                    DEFAULT_WEIGHTS; historical precision helpers

  action/src/audit_packs_action/
    engines.py      CheckovEngine / SemgrepEngine / CodeQLEngine (async);
                    ASTEngine (in-process AST visitors); run_git_diff()
    report.py       build_comments(); build_summary_comment(); gate_failed();
                    build_coverage_matrix(md/html); build_sarif();
                    post_review() [GitHub IO]; write_job_summary()
    cli.py          analyze() + assess() + main() — env-driven orchestrator

packs/
  nist-800-53/controls.yaml    canonical pack: (engine, check_id) → control
  soc2/controls.yaml           crosswalk → nist-800-53 via maps_to
  gdpr/controls.yaml           crosswalk → nist-800-53
  hipaa/controls.yaml          crosswalk → nist-800-53
  iso27001/controls.yaml       crosswalk → nist-800-53
  pci-dss/controls.yaml        crosswalk → nist-800-53
  fedramp/controls.yaml        crosswalk → nist-800-53
  org-policy/controls.yaml     example org-policy pack (crosswalk → nist-800-53)

rules/
  weak-cipher.yaml        Semgrep — detect weak TLS/cipher config
  no-tls-verify.yaml      Semgrep — detect TLS verification disabled
  pii-fields.yaml         Semgrep — detect PII field names in IaC
  insecure-config.yaml    Semgrep — detect insecure default settings
  hardcoded-credential.yaml  Semgrep — detect secrets in IaC
  overpermissive-iam.yaml    Semgrep — detect wildcard IAM permissions
  missing-audit-log.yaml     Semgrep — detect absent audit logging config

examples/
  workflows/          Ready-to-copy GitHub Actions workflow files
  audit-models/       Provider-specific model routing YAML files
  org-policy/         Example org-policy packs (fintech, healthcare, saas-startup)
```

### Module boundaries and I/O

Network and subprocess I/O are confined to exactly four modules:

| Module | External I/O |
|---|---|
| `engines.py` | Spawns Checkov/Semgrep/CodeQL subprocesses; calls `git diff` |
| `evidence.py` | GitHub PR context API |
| `adjudicate.py` | LLM provider HTTP APIs |
| `report.py` | GitHub review API |

Every other module — `normalize`, `diff`, `packs`, `dataflow`, `confidence`, `coverage`, `oscal` — is pure Python. You can test them without any network access, installed tools, or API keys.

---

## 7. Adding a new framework pack

A pack is a YAML file in `packs/`. There are two kinds:

### Canonical pack

Used only for NIST 800-53. Maps `(engine, check_id)` pairs directly to control IDs.

```yaml
schema_version: "2"
framework: nist-800-53
title: NIST SP 800-53 Rev 5
controls:
  - id: SC-13
    title: Cryptographic Protection
    mappings:
      - { engine: checkov, check_id: CKV_AWS_19 }
      - { engine: checkov, check_id: CKV_AWS_5 }
      - { engine: semgrep,  check_id: audit-packs.weak-cipher }
    evidence_requirements:
      - { type: code_snippet, description: "Encryption algorithm used" }
```

### Crosswalk pack

Used for every other framework. Controls map to one or more NIST 800-53 controls via `maps_to`. The detection logic is inherited from the NIST pack — no check IDs are duplicated.

```yaml
schema_version: "2"
framework: my-framework
title: My Framework v1
crosswalk: nist-800-53

controls:
  - id: MF-1.1
    title: Encryption at rest
    maps_to: SC-13

  - id: MF-1.2
    title: Transmission security
    maps_to: SC-8

  # Governance controls with no IaC-observable checks use assessment: manual
  - { id: MF-2.1, title: Policy review, assessment: manual }
```

### Step-by-step: add a crosswalk pack

1. Create `packs/my-framework/controls.yaml` following the crosswalk schema above. Use an existing pack like `packs/soc2/controls.yaml` as a reference.

2. Verify the pack loads without error:

   ```bash
   python3 -c "
   from audit_packs_mapping.packs import load_pack
   pack = load_pack('packs/my-framework')
   print(f'Loaded {len(pack[\"controls\"])} controls')
   "
   ```

3. Verify control mapping resolves correctly:

   ```bash
   python3 -c "
   from audit_packs_core.models import Finding
   from audit_packs_mapping.packs import map_findings
   f = Finding('CKV_AWS_19', 'checkov', 'main.tf', 1, 'high', 'msg', 'ev')
   cfs = map_findings([f], 'packs', ['my-framework'])
   for cf in cfs:
       print(cf.framework, cf.control_id, cf.control_title)
   "
   ```

4. Add tests to `tests/test_packs.py`. At a minimum: one test that verifies a known check ID resolves to the expected control, and one that verifies `assessment: manual` controls are present in `iter_controls()` output.

5. Register the framework ID in `agents.py` `build_agents()` if you need custom detection logic beyond what Checkov/Semgrep provide. Framework agents follow the `DetectionAgent.detect() → SARIF dict` contract — they do not call `map_findings`, they only emit raw findings.

6. If you are adding a new Semgrep rule to support the pack, add the `.yaml` rule file to `rules/` and reference it in the canonical NIST pack under the appropriate control.

### Pack validation rules

`load_pack()` in `packs.py` enforces these requirements and raises `ValueError` if they are not met:

- Top-level keys `framework`, `title`, and `controls` must be present; `schema_version: "2"` is required.
- Crosswalk packs must set `crosswalk: nist-800-53`.
- Each control with `maps_to` must reference control IDs that exist in the NIST pack.
- Severity vocabulary is fixed: `low`, `medium`, `high`, `critical`.

---

## 8. Running the action locally

### Option A — Docker (closest to CI)

```bash
# Build the image
docker build -t audit-packs:dev .

# Run against the current repo directory
# GITHUB_TOKEN is required for evidence enrichment and posting comments.
# Set ADJUDICATION_MODE=off to skip LLM calls during local testing.
docker run --rm \
  -e FRAMEWORKS=nist-800-53,soc2 \
  -e FAIL_ON=high \
  -e SCAN_MODE=diff \
  -e ADJUDICATION_MODE=off \
  -e GITHUB_TOKEN=<your-token> \
  -e PR_NUMBER=<pr-number> \
  -e BASE_REF=origin/main \
  -v "$(pwd):/github/workspace" \
  -w /github/workspace \
  audit-packs:dev
```

### Option B — CLI without Docker

```bash
# Activate the venv first
source .venv/bin/activate

export FRAMEWORKS=nist-800-53,soc2
export FAIL_ON=high
export SCAN_MODE=diff
export ADJUDICATION_MODE=off
export GITHUB_TOKEN=<your-token>
export PR_NUMBER=<pr-number>
export BASE_REF=origin/main

python -m audit_packs_action.cli
```

### Minimal GitHub Actions workflow

Copy `examples/workflows/basic.yml` into your repository as `.github/workflows/audit.yml`:

```yaml
name: Audit Packs
on:
  pull_request:

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # required for diff scanning

      - uses: prakharsingh/audit-packs@v1
        with:
          frameworks: nist-800-53,soc2
          fail-on: high
```

`fetch-depth: 0` is required. Without it, `git diff` cannot reach the base ref and the diff path will produce no findings.

Additional workflow examples are in `examples/workflows/`: with CodeQL, with AI adjudication, multi-framework combinations, and a scheduled full-posture run.

---

## 9. Key design rules

These rules exist to keep the project maintainable and the test suite fast. Please read them before making changes.

**Never re-implement detection logic.** Checkov, Semgrep, and CodeQL are invoked as subprocesses. The project's job is to normalise, map, and communicate their output — not to add new detection rules except as authored Semgrep YAML files in `rules/`.

**Packs are data, not code.** A framework pack is a YAML mapping. Logic that interprets packs lives only in `packs.py`. If you find yourself writing Python that encodes compliance knowledge, it belongs in a pack instead.

**SARIF is the lingua franca.** Every engine and every detection agent emits SARIF. `normalize.py` is the only place that converts SARIF to `Finding` dataclasses. Nothing else should parse SARIF directly.

**Detection agents also emit SARIF.** The framework agents in `agents.py` implement `DetectionAgent.detect() → SARIF dict`. They follow the same contract as the scanner engines. This is enforced by the `DetectionAgent` ABC.

**Diff-filtered only on the diff path.** The severity gate and inline PR comments cover only lines added or changed in the PR. Full-scan findings do not trigger the gate and are not posted as inline comments.

**I/O is confined.** The four I/O modules listed in the [module boundaries](#module-boundaries-and-io) section are the only places that make network calls or spawn subprocesses. Keep it that way.

**Severity vocabulary is fixed.** Use exactly `low`, `medium`, `high`, `critical`. No other values.

**License.** Apache-2.0. No paid-tier engine features (Semgrep Pro, Bearer Pro, Checkov Enterprise) may be required.
