# audit-packs

[![PyPI version](https://img.shields.io/pypi/v/audit-packs.svg)](https://pypi.org/project/audit-packs/)
[![Python](https://img.shields.io/pypi/pyversions/audit-packs.svg)](https://pypi.org/project/audit-packs/)
[![Downloads](https://img.shields.io/pypi/dm/audit-packs.svg)](https://pypi.org/project/audit-packs/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/prakharsingh/audit-packs/blob/main/LICENSE)
[![GitHub Repository](https://img.shields.io/badge/GitHub-audit--packs-181717?logo=github)](https://github.com/prakharsingh/audit-packs)

<p align="center">
  <img src="https://raw.githubusercontent.com/prakharsingh/audit-packs/main/cover.jpg" alt="Audit-Packs Banner" width="100%" />
</p>

An evidence-first **Compliance Intelligence Engine** that transforms security scanner findings into standardized, evidence-backed compliance artifacts (inline PR comments, OSCAL assessment results, SARIF, and control coverage reports).

---

## 🔍 The Problem
Modern security scanners (such as Checkov, Semgrep, Trivy, tfsec, and gitleaks) are highly effective at identifying infrastructure-as-code (IaC) misconfigurations and software vulnerabilities. However, they are scanner-centric and do not directly answer the critical questions that governance, risk, and compliance (GRC) teams or auditors ask:
*   *Which compliance controls (e.g., NIST 800-53, SOC 2, HIPAA, GDPR) are affected by this finding?*
*   *Where is the exact code/configuration evidence to prove compliance or violation?*
*   *How do we avoid false-positive alerts bloating our engineering workflows?*

## 💡 The Solution
`audit-packs` bridges the gap by providing a scanner-agnostic mapping, enrichment, and consensus layer. Rather than replacing existing detection tools, it takes their output (typically via SARIF), normalizes it, enriches it with codebase/git evidence context, maps the findings to GRC control requirements, and optionally filters noise using an AI consensus ensemble.

---

## 📦 Installation

To run `audit-packs` locally as a CLI tool:

```bash
# Install audit-packs CLI via pip
pip install audit-packs

# Or install in an isolated environment via pipx (recommended)
pipx install audit-packs
```

> **Note:** Detection is delegated to best-in-class open-source engines. For the scanners to run, ensure they are installed on your system path, or inject them into the `pipx` environment:
> ```bash
> pipx inject audit-packs checkov semgrep
> ```

---

## 🚀 Quick Start

### 1. Initialize Configuration
Bootstrap your repository with a default configuration and download local compliance packs:
```bash
audit-packs --init
```

### 2. Run a Compliance Scan
Scan your workspace and map findings to NIST 800-53 and SOC 2 frameworks:
```bash
audit-packs --frameworks nist-800-53,soc2
```

---

## 📋 CLI Command Matrix & Flags

| Flag | Default | Description |
|---|---|---|
| `--frameworks` | **Required** | Comma-separated list of framework pack IDs to evaluate (e.g., `nist-800-53,soc2`). |
| `--fail-on` | `high` | Minimum finding severity to exit with a non-zero status. Options: `low`, `medium`, `high`, `critical`. |
| `--scan-mode` | `both` | Scan scope: `diff` (PR-changed lines only), `full` (entire posture), or `both`. |
| `--base-ref` | `origin/main` | Target base git reference for diff-only scanning. |
| `--packs-dir` | *bundled* | Path to custom compliance pack YAML directory. |
| `--rules-path` | *bundled* | Path to Semgrep rule files. |
| `--emit-oscal` | `true` | Generate an OSCAL `assessment-results` JSON document (`oscal.json`). |
| `--emit-coverage` | `true` | Generate markdown/HTML control coverage matrix files (`coverage.md`/`coverage.html`). |
| `--emit-sarif` | `true` | Generate an aggregated SARIF report file (`audit-packs.sarif`). |
| `--adjudication-mode` | `off` | AI consensus adjudication: `off` (disabled), `advisory` (score findings), or `enforce` (suppress low-confidence findings). |
| `--min-confidence` | `0.70` | Composite confidence score threshold (0.0 to 1.0) under `enforce` mode. |
| `--init` | *N/A* | Interactive config bootstrapper wizard. |
| `--validate-policy` | *N/A* | Syntax validation command for custom compliance pack YAMLs. |

---

## 🌐 GitHub Action Integration
`audit-packs` is designed to run seamlessly in GitHub Action pipelines to block compliance regressions on pull requests.

```yaml
# .github/workflows/compliance-audit.yml
name: Compliance Audit

on:
  pull_request:

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write # Required to post inline review comments

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Required for diff-only scanning

      - name: Run Audit Packs compliance check
        uses: prakharsingh/audit-packs@v1
        with:
          frameworks: nist-800-53,soc2
          fail-on: high
```

---

## 📊 Supported Compliance Frameworks
Compliance frameworks are defined as declarative YAML packs. The following packs are supported:

| Framework | Pack ID | Automated Controls |
|---|---|---|
| **NIST SP 800-53 Rev 5** | `nist-800-53` | 20 (Canonical baseline) |
| **SOC 2 Type II** | `soc2` | 17 (Technical criteria) |
| **ISO/IEC 27001:2022** | `iso27001` | 10 |
| **PCI-DSS v4.0** | `pci-dss` | 8 |
| **FedRAMP Moderate** | `fedramp` | 8 |
| **HIPAA Security Rule** | `hipaa` | 6 |
| **GDPR** | `gdpr` | 5 |
| **Custom Org-Policy** | `org-policy` | Configurable |

---

## 📤 Output Artifacts
*   **Inline PR Comments:** Posts targeted comments containing control mappings and cryptographic/configuration evidence on changed lines of a PR.
*   **OSCAL Assessment Results:** Machine-readable `oscal.json` compliant with NIST SP 800-53 GRC tooling workflows.
*   **Coverage Reports:** Beautiful `coverage.md` and `coverage.html` containing an audit-ready compliance matrix.
*   **Aggregated SARIF:** A combined `audit-packs.sarif` file containing all scanner findings mapped to controls.

---

## 📦 Ecosystem Architecture

`audit-packs` is built as a modular ecosystem consisting of five Python packages:

| Package | PyPI Link | Role | Standalone? |
|---|---|---|---|
| **`audit-packs`** | [![PyPI](https://img.shields.io/pypi/v/audit-packs.svg)](https://pypi.org/project/audit-packs/) | Main CLI & Action entrypoint | **Yes** |
| [`audit-packs-core`](https://pypi.org/project/audit-packs-core/) | [![PyPI](https://img.shields.io/pypi/v/audit-packs-core.svg)](https://pypi.org/project/audit-packs-core/) | Primitives, diff parsing, normalization | No |
| [`audit-packs-mapping`](https://pypi.org/project/audit-packs-mapping/) | [![PyPI](https://img.shields.io/pypi/v/audit-packs-mapping.svg)](https://pypi.org/project/audit-packs-mapping/) | Compliance pack loader & OSCAL exporter | No |
| [`audit-packs-evidence`](https://pypi.org/project/audit-packs-evidence/) | [![PyPI](https://img.shields.io/pypi/v/audit-packs-evidence.svg)](https://pypi.org/project/audit-packs-evidence/) | Evidence collectors & heuristic agents | No |
| [`audit-packs-ai`](https://pypi.org/project/audit-packs-ai/) | [![PyPI](https://img.shields.io/pypi/v/audit-packs-ai.svg)](https://pypi.org/project/audit-packs-ai/) | LLM consensus & confidence scoring | No |

---

## 🤝 Contributing & Backtrack Links
*   **GitHub Repository:** [https://github.com/prakharsingh/audit-packs](https://github.com/prakharsingh/audit-packs)
*   **Issue Tracker:** [https://github.com/prakharsingh/audit-packs/issues](https://github.com/prakharsingh/audit-packs/issues)
*   **Contributing Guidelines:** Refer to the repository [CONTRIBUTING.md](https://github.com/prakharsingh/audit-packs/blob/main/CONTRIBUTING.md).

## 📄 License
This project is licensed under the Apache-2.0 License. See the [LICENSE](https://github.com/prakharsingh/audit-packs/blob/main/LICENSE) file in the main repository for details.
