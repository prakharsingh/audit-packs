# audit-packs-core

[![PyPI version](https://img.shields.io/pypi/v/audit-packs-core.svg)](https://pypi.org/project/audit-packs-core/)
[![Python](https://img.shields.io/pypi/pyversions/audit-packs-core.svg)](https://pypi.org/project/audit-packs-core/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/prakharsingh/audit-packs/blob/main/LICENSE)
[![GitHub Repository](https://img.shields.io/badge/GitHub-audit--packs-181717?logo=github)](https://github.com/prakharsingh/audit-packs)

<p align="center">
  <img src="https://raw.githubusercontent.com/prakharsingh/audit-packs/main/cover.jpg" alt="Audit-Packs Banner" width="100%" />
</p>

`audit-packs-core` contains the foundational models, normalization logic, git diff parser, and source-to-sink data-flow primitives for the `audit-packs` ecosystem.

> ⚠️ **IMPORTANT: This is a sub-package of the `audit-packs` compliance mapping toolkit. It is NOT designed to be run as a standalone CLI tool.** If you are looking for the main CLI and GitHub Action scanner execution engine, please install and refer to [audit-packs](https://pypi.org/project/audit-packs/).

---

## 📦 Installation

You can install this package via `pip` if you are writing custom extensions or building on top of the `audit-packs` data structures:

```bash
pip install audit-packs-core
```

---

## 🛠️ API Surface & Modules

| Module | Key API Exports | Description |
|---|---|---|
| `audit_packs_core.models` | `Finding`, `ControlFinding`, `ControlStatus`, `AdjudicationResult` | Core compliance structures and type schemas. |
| `audit_packs_core.normalize` | `sarif_to_findings()`, `extract_rule_confidences()` | Standardizes engine-specific SARIF JSON outputs into standard Finding instances. |
| `audit_packs_core.diff` | `parse_unified_diff()` | Compares line numbers between refs to filter PR-changed lines. |
| `audit_packs_core.dataflow` | `extract_data_flows()`, `flow_confidence()` | Tracks source-to-sink data flow dependencies (Python/YAML/HCL). |

---

## 📦 Ecosystem Architecture

`audit-packs` is built as a modular ecosystem consisting of five Python packages:

| Package | PyPI Link | Role | Standalone? |
|---|---|---|---|
| [`audit-packs`](https://pypi.org/project/audit-packs/) | [pypi](https://pypi.org/project/audit-packs/) | Main CLI & Action entrypoint | **Yes** |
| **`audit-packs-core`** | [pypi](https://pypi.org/project/audit-packs-core/) | Primitives, diff parsing, normalization | No |
| [`audit-packs-mapping`](https://pypi.org/project/audit-packs-mapping/) | [pypi](https://pypi.org/project/audit-packs-mapping/) | Compliance pack loader & OSCAL exporter | No |
| [`audit-packs-evidence`](https://pypi.org/project/audit-packs-evidence/) | [pypi](https://pypi.org/project/audit-packs-evidence/) | Evidence collectors & heuristic agents | No |
| [`audit-packs-ai`](https://pypi.org/project/audit-packs-ai/) | [pypi](https://pypi.org/project/audit-packs-ai/) | LLM consensus & confidence scoring | No |

---

## 🔗 Related Resources
*   **Main GitHub Repository:** [https://github.com/prakharsingh/audit-packs](https://github.com/prakharsingh/audit-packs)
*   **Documentation & Setup:** [docs/SETUP.md](https://github.com/prakharsingh/audit-packs/blob/main/docs/SETUP.md)
*   **Issue Tracker:** [https://github.com/prakharsingh/audit-packs/issues](https://github.com/prakharsingh/audit-packs/issues)

## 📄 License
This library is licensed under the Apache-2.0 License. See the [LICENSE](https://github.com/prakharsingh/audit-packs/blob/main/LICENSE) file in the main repository for details.
