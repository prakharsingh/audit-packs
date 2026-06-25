# audit-packs

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

<p align="center">
  <img src="cover.jpg" alt="Audit-Packs Banner" width="100%" />
</p>

> Map IaC security findings to compliance framework controls and post evidence-backed, control-tagged inline PR review comments with a configurable severity gate.

Detection is delegated entirely to best-in-class OSS engines (Checkov, Semgrep, optionally CodeQL). What this action adds is the **control mapping + evidence + PR UX layer**: reviewers see not just "S3 bucket unencrypted" but:

> **NIST 800-53 / SC-13 — Cryptographic Protection**
> Severity: `high` | Engine: `checkov` (`CKV_AWS_19`)
> Evidence: `server_side_encryption_configuration is not set`

---

## Why this exists

Checkov and Semgrep are excellent at finding IaC misconfigurations. They are not designed to answer the question auditors and GRC teams actually ask: *which compliance controls are affected, and where is the evidence?* audit-packs bridges that gap by wrapping detection output in a compliance control mapping layer, confidence scoring, and audit-grade evidence packaging — without replacing or re-implementing any detection engine.

---

## Quick start

```yaml
# .github/workflows/audit.yml
name: Audit Packs

on:
  pull_request:

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write   # required to post inline review comments

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # required for diff-only scanning

      - uses: prakharsingh/audit-packs@v1
        with:
          frameworks: nist-800-53,soc2
          fail-on: high
```

The action posts inline review comments on changed lines only, writes an OSCAL assessment-results JSON, a control coverage matrix, and an aggregate SARIF file, then exits non-zero if any finding meets or exceeds `fail-on`.

---

## Inputs

| Input | Default | Description |
|---|---|---|
| `frameworks` | **required** | Comma- or newline-separated pack IDs to evaluate. See [Framework coverage](#framework-coverage). |
| `fail-on` | `high` | Minimum severity that fails the check. One of `low`, `medium`, `high`, `critical`. |
| `base-ref` | `origin/main` | Base git ref to diff against. Change for non-standard default branch names. |
| `scan-mode` | `both` | `diff` — PR comments + gate only. `full` — posture outputs only. `both` — all paths (recommended). |
| `emit-oscal` | `true` | Write OSCAL assessment-results JSON to `oscal.json`. |
| `emit-coverage` | `true` | Write a control coverage matrix to `coverage.md` / `coverage.html` and append to the job summary. |
| `emit-sarif` | `true` | Write an aggregate SARIF file to `audit-packs.sarif`. |
| `adjudication-mode` | `off` | LLM adjudication: `off` (disabled), `advisory` (score and log, no filtering), `enforce` (suppress findings below `min-confidence`). |
| `min-confidence` | `0.70` | Composite confidence threshold (0.0–1.0). Findings below this are suppressed in `enforce` mode. |
| `models-config` | `audit-models.yaml` | Repo-relative path to a model routing YAML that maps roles to providers. Falls back to built-in defaults if absent. |
| `detector-model` | `""` | Override the `detector` role's model (sets `DETECTOR_MODEL` env). |
| `verifier-model` | `""` | Override the `verifier` role's model (sets `VERIFIER_MODEL` env). |
| `adversarial-model` | `""` | Override the `adversarial` role's model (sets `ADVERSARIAL_MODEL` env). |
| `judge-model` | `""` | Override the `judge` role's model (sets `JUDGE_MODEL` env). |
| `codeql-sarif` | `""` | Repo-relative path to directory of CodeQL SARIF files. Gracefully skipped if absent. |
| `ast-rules` | `ast-rules` | Path to Tree-sitter AST rule scripts directory (reserved for Phase 2; ignored in Phase 1). |

## Outputs

| Output | Path | Description |
|---|---|---|
| `oscal-path` | `oscal.json` | OSCAL assessment-results document for audit evidence packages. |
| `coverage-md-path` | `coverage.md` | Markdown control coverage matrix. |
| `coverage-html-path` | `coverage.html` | HTML control coverage matrix. |
| `sarif-path` | `audit-packs.sarif` | Aggregate SARIF file for upload to GitHub Code Scanning. |

---

## Outputs in depth

### Inline PR comments

For every finding on a changed line, the action posts a review comment:

> **Compliance control touched: `nist-800-53` / SC-13 — Cryptographic Protection**
>
> - Severity: `high`
> - Engine: `checkov` (`CKV_AWS_19`)
> - Finding: Ensure S3 bucket has encryption enabled
>
> Evidence:
> ```
> server_side_encryption_configuration is not set
> ```

Comments are **diff-filtered**: only findings on lines added or modified in the PR are posted. Findings on unchanged lines are silently dropped.

### OSCAL assessment-results

When `emit-oscal: true`, the action writes an [OSCAL assessment-results](https://pages.nist.gov/OSCAL/) document to `oscal.json`. This is the machine-readable format GRC tools and FedRAMP / NIST 800-53 evidence packages expect.

```yaml
- uses: prakharsingh/audit-packs@v1
  id: audit

- name: Upload OSCAL evidence
  uses: actions/upload-artifact@v4
  with:
    name: oscal-assessment-results
    path: ${{ steps.audit.outputs.oscal-path }}
```

### Control coverage matrix

When `emit-coverage: true`, the action writes `coverage.md` and `coverage.html` and appends the matrix to the Actions job summary. The matrix lists every control in the selected frameworks, whether it is automatically assessable via IaC checks, and its current pass / fail / not-applicable status.

### Aggregate SARIF and GitHub Code Scanning

When `emit-sarif: true`, findings across all engines are merged into a single SARIF file. Upload it to GitHub Code Scanning for a unified security overview:

```yaml
- uses: prakharsingh/audit-packs@v1

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: audit-packs.sarif
```

---

## Framework coverage

| Framework | Pack ID | Type | Automated controls |
|---|---|---|---|
| NIST SP 800-53 Rev 5 | `nist-800-53` | Canonical | 20 |
| SOC 2 Type II (AICPA 2017) | `soc2` | Crosswalk → NIST 800-53 | 17 of 39 (22 are governance-only) |
| ISO/IEC 27001:2022 | `iso27001` | Crosswalk → NIST 800-53 | 10 |
| PCI-DSS v4.0 | `pci-dss` | Crosswalk → NIST 800-53 | 8 |
| FedRAMP Moderate | `fedramp` | Crosswalk → NIST 800-53 | 8 |
| HIPAA Security Rule | `hipaa` | Crosswalk → NIST 800-53 | 6 |
| GDPR (technical controls) | `gdpr` | Crosswalk → NIST 800-53 | 5 |
| Org-policy (custom) | `org-policy` | Crosswalk → NIST 800-53 | 6 (configurable) |

NIST 800-53 is the canonical pack. Every other framework is a crosswalk pack: each control maps to one or more NIST controls, which resolve to engine check IDs. Adding a new framework never requires touching detection logic — you add a YAML pack.

---

## Scan modes

| Mode | What runs | Use case |
|---|---|---|
| `diff` | PR inline comments + severity gate | Fast PR feedback; no posture outputs |
| `full` | Coverage matrix, OSCAL, aggregate SARIF | Scheduled compliance snapshots; no PR gate |
| `both` | All of the above (default) | Recommended for PRs — gate on every push, posture on every merge |

---

## How it works

```
git diff ──────────────────────────────────────────────────────────────────────┐
                                                                               │ diff-filter
Checkov ──────────► SARIF ─┐                                                   │ (PR-changed
Semgrep ──────────► SARIF ─┤                                                   │  lines only)
CodeQL (optional) ► SARIF ─┤                                                   │
Detection agents  ► SARIF ─┴──► normalize ──► Finding[]                        │
  (GDPR, HIPAA,                                   │                            │
   SOC2, FedRAMP,                           enrich (evidence +                 │
   OrgPolicy,                               doc context)                       │
   DataFlow)                                      │                            │
                                            data-flow analysis                 │
                                                  │                            │
                                                  └──── diff-filtered ─────────┤
                                                                               │
                                      ┌────────────────────────────────────────┘
                                      ▼
                           map to framework controls
                                      │
                             adjudicate (AI ensemble,
                             if enabled)
                                      │
                             confidence gate
                                      │
                    ┌─────────────────┼──────────────────────┐
                    ▼                 ▼                       ▼
             PR inline comments  severity gate         posture outputs
             (control-tagged,    (exit 1 if ≥          (OSCAL, coverage
              evidence-backed)    fail-on threshold)     matrix, SARIF)
```

**Detection is never re-implemented.** Checkov, Semgrep, and CodeQL run as subprocesses and emit SARIF. Framework-specific detection agents (`GDPRAgent`, `HIPAAAgent`, `SOC2Agent`, `FedRAMPAgent`, `OrgPolicyAgent`, `DataFlowAgent`) apply heuristics for controls that engines cannot observe directly — they also emit SARIF. `normalize.py` converts all SARIF to a common `Finding` model. Pack YAML files map `(engine, check_id)` pairs to control IDs.

### Authored Semgrep rules

Seven rules ship alongside the action to cover gaps not detectable by Checkov:

| Rule ID | What it catches |
|---|---|
| `weak-cipher` | DES / RC4 / MD5 usage in Python |
| `hardcoded-credential` | Secrets assigned to variables |
| `no-tls-verify` | TLS verification disabled |
| `overpermissive-iam` | Wildcard IAM actions or resources |
| `missing-audit-log` | Logging / audit trail not configured |
| `insecure-config` | Insecure configuration flags (debug mode, plaintext storage) |
| `pii-fields` | PII field names in data models and API schemas |

---

## AI adjudication

When `adjudication-mode` is `advisory` or `enforce`, each finding passes through a four-role LLM ensemble before the confidence gate:

1. **Detector** — establishes an initial confidence assessment, acting as a compliance auditor.
2. **Verifier** — argues why the finding is a genuine compliance violation.
3. **Adversarial** — argues why the finding is a false positive.
4. **Judge** — weighs both arguments and produces the final consensus score.

### Confidence scoring

The final composite score is a weighted average of six signals:

| Signal | Weight | Source |
|---|---|---|
| Rule confidence | 20% | Emitted by the engine or agent in SARIF |
| Data-flow confidence | 20% | Source-to-sink flow analysis (`dataflow.py`) |
| Model consensus | 25% | Judge's agreement score from the AI ensemble |
| Evidence confidence | 15% | Richness of code snippets and PR / commit file context |
| Control severity | 10% | Criticality rank of the mapped control |
| Historical precision | 10% | Long-term true-positive rate tracked per check ID |

A finding whose composite score falls below `min-confidence` (default `0.70`) is suppressed when `adjudication-mode: enforce`. In `advisory` mode the score is logged but no finding is filtered. In `off` mode (default) no LLM calls are made.

### Configuring model routing

Create `audit-models.yaml` in your repo root to map each role to a provider and model. The action falls back to built-in defaults if the file is absent.

```yaml
# audit-models.yaml
models:
  detector:
    provider: openai
    model: gpt-4o
    api_key_env: OPENAI_API_KEY

  verifier:
    provider: anthropic
    model: claude-opus-4-5
    api_key_env: ANTHROPIC_API_KEY

  adversarial:
    provider: google
    model: gemini-1.5-pro
    api_key_env: GOOGLE_API_KEY

  judge:
    provider: openai
    model: gpt-4o
    api_key_env: OPENAI_API_KEY
```

Supported providers: `openai`, `anthropic`, `google`, `ollama`, `openai-compatible`. Supply the corresponding API key secrets as environment variables on the step.

You can also override individual roles without a config file using per-role inputs:

```yaml
- uses: prakharsingh/audit-packs@v1
  with:
    frameworks: nist-800-53
    adjudication-mode: enforce
    judge-model: gpt-4o-mini   # cheaper judge for high-volume repos
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    GOOGLE_API_KEY: ${{ secrets.GOOGLE_API_KEY }}
```

---

## Custom org-policy pack

Edit `packs/org-policy.yaml` to define internal controls and map them to NIST 800-53 controls:

```yaml
id: org-policy
title: Acme Corp Security Policy
crosswalk: nist-800-53

controls:
  - { id: ACME-ENC-1, title: All data stores must be encrypted at rest, maps_to: [SC-13, SC-28] }
  - { id: ACME-NET-1, title: No public S3 buckets permitted,            maps_to: [SC-7] }
  - { id: ACME-LOG-1, title: Enable audit logging for all services,     maps_to: [AU-2] }
```

Any check ID already mapped in `nist-800-53.yaml` is automatically surfaced under your org control ID with no other changes required.

---

## CodeQL integration

audit-packs can consume CodeQL SARIF artifacts to combine SAST findings with IaC findings in a single compliance view. Run `codeql-action/analyze` with `upload: false`, then pass the output directory to audit-packs:

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    languages: python,javascript

- name: Perform CodeQL Analysis
  uses: github/codeql-action/analyze@v3
  with:
    output: codeql-results   # write SARIF to this directory
    upload: false            # prevent double-upload; audit-packs handles it

- uses: prakharsingh/audit-packs@v1
  with:
    frameworks: nist-800-53,soc2
    codeql-sarif: codeql-results
```

If `codeql-sarif` is absent or the directory is empty, CodeQL findings are silently skipped — the rest of the scan runs normally.

---

## Local development

**Prerequisites:** Python 3.11+, `git`

```bash
# Clone and set up a virtual environment
git clone https://github.com/prakharsingh/audit-packs.git
cd audit-packs
python -m venv .venv
source .venv/bin/activate

# Install in editable mode (includes Checkov and Semgrep)
pip install -e ".[dev]"

# Verify engines are on PATH
checkov --version
semgrep --version

# Run all tests
pytest -v

# Run a single test file
pytest tests/test_packs.py -v

# Run a single test
pytest tests/test_packs.py::test_map_findings_crosswalk_soc2 -v
```

**Build the Docker action image:**

```bash
docker build -t audit-packs:dev .
```

**Run the Docker smoke test:**

```bash
pytest tests/test_docker_smoke.py -v
# or directly:
./tests/docker_smoke.sh
```

### Project layout

```
src/audit_packs/
  models.py      # Finding, ControlFinding, ControlStatus, AdjudicationResult dataclasses
  diff.py        # parse_unified_diff() → {file: set[line]}
  normalize.py   # sarif_to_findings(); extract_rule_confidences()
  engines.py     # CheckovEngine, SemgrepEngine, CodeQLEngine (async + sync fallback)
  agents.py      # GDPRAgent, HIPAAAgent, SOC2Agent, FedRAMPAgent, OrgPolicyAgent, DataFlowAgent
  packs.py       # load_pack(), map_findings() — control mapping + NIST crosswalk resolution
  evidence.py    # enrich(), fetch_pr_context() [GitHub API], evidence_confidence()
  dataflow.py    # extract_data_flows() (Python / HCL / YAML), flow_confidence()
  adjudicate.py  # AI ensemble (detector → verifier → adversarial → judge) [LLM HTTP]
  confidence.py  # score_finding(), apply_confidence_gate(), DEFAULT_WEIGHTS
  coverage.py    # compute_coverage() → list[ControlStatus]
  oscal.py       # to_assessment_results() — NIST OSCAL assessment-results JSON
  report.py      # build_comments(), post_review(), build_coverage_matrix(), build_sarif()
  cli.py         # analyze() (diff path) + assess() (full path) + main()

packs/           # Framework YAML packs (data only — no detection logic)
  nist-800-53.yaml          # canonical: (engine, check_id) → control
  soc2.yaml, gdpr.yaml, hipaa.yaml, iso27001.yaml,
  pci-dss.yaml, fedramp.yaml, org-policy.yaml   # crosswalk → nist-800-53

rules/           # Authored Semgrep rules bundled with the action
  weak-cipher.yaml  no-tls-verify.yaml  pii-fields.yaml
  insecure-config.yaml  hardcoded-credential.yaml
  overpermissive-iam.yaml  missing-audit-log.yaml
```

**Key design constraints:**
- Detection is never re-implemented. Engines run as subprocesses; findings arrive as SARIF.
- Packs are data, not code. A framework pack is pure YAML mapping check IDs to controls.
- Network and subprocess I/O is confined to four modules: `engines.py`, `evidence.py`, `adjudicate.py`, `report.py`. Everything else is pure Python and testable without network access or installed tools.

---

## Contributing

Issues and pull requests are welcome. Please open an issue before starting significant work so we can align on scope.

**Adding a framework pack:**

1. Create `packs/<framework-id>.yaml` with `crosswalk: nist-800-53` and a list of controls, each with a `maps_to:` list of NIST control IDs.
2. Add corresponding detection coverage in the appropriate agent in `agents.py` if the framework requires heuristics beyond Checkov / Semgrep check IDs.
3. Add a test in `tests/test_packs.py` covering the new crosswalk.

**Adding a Semgrep rule:**

1. Add the rule YAML to `rules/`.
2. Map the new rule ID to the appropriate NIST control(s) in `packs/nist-800-53.yaml`.
3. Add a fixture and test in `tests/test_rules.py`.

---

## License

[Apache-2.0](LICENSE)
