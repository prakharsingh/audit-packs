# audit-packs-evidence

[![PyPI version](https://img.shields.io/pypi/v/audit-packs-evidence.svg)](https://pypi.org/project/audit-packs-evidence/)
[![Python](https://img.shields.io/pypi/pyversions/audit-packs-evidence.svg)](https://pypi.org/project/audit-packs-evidence/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/prakharsingh/audit-packs/blob/main/LICENSE)
[![GitHub Repository](https://img.shields.io/badge/GitHub-audit--packs-181717?logo=github)](https://github.com/prakharsingh/audit-packs)

<p align="center">
  <img src="https://raw.githubusercontent.com/prakharsingh/audit-packs/main/cover.jpg" alt="Audit-Packs Banner" width="100%" />
</p>

`audit-packs-evidence` provides codebase metadata extraction, evidence enrichment, and compliance-specific detection agents for the `audit-packs` ecosystem.

> ⚠️ **IMPORTANT: This is a sub-package of the `audit-packs` compliance mapping toolkit. It is NOT designed to be run as a standalone CLI tool.** If you are looking for the main CLI and GitHub Action scanner execution engine, please install and refer to [audit-packs](https://pypi.org/project/audit-packs/).

---

## 📦 Installation

Install this package via `pip` if you are constructing custom evidence collection or developing additional detection agents:

```bash
pip install audit-packs-evidence
```

---

## 🛠️ API Surface & Modules

| Module | Key API Exports | Description |
|---|---|---|
| `audit_packs_evidence.evidence` | `enrich()`, `fetch_pr_context()`, `evidence_confidence()` | Fetches Git, PR, and local file context to attach cryptographic/audit-ready evidence strings. |
| `audit_packs_evidence.agents` | `GDPRAgent`, `HIPAAAgent`, `SOC2Agent`, `FedRAMPAgent`, `OrgPolicyAgent`, `DataFlowAgent`, `Nist80053Agent` | Framework-specific detection agents running heuristics not coverable by traditional static engines. |

### 🔍 Specialized Detection Agents
Some compliance controls require auditing codebase configuration states that standard IaC tools do not cover. The package bundles programmatic agents:
*   **`Nist80053Agent`:** Automatically scans configuration manifests (such as `requirements.txt`, `pyproject.toml`, `package.json`, and `Cargo.toml`) to detect unpinned dependencies and wildcards, mapping findings directly to the NIST SI-2 (Flaw Remediation) control.
*   **`DataFlowAgent`:** Runs source-to-sink dependency flow tracing to measure flow-sensitive compliance risks.

---

## 📦 Ecosystem Architecture

`audit-packs` is built as a modular ecosystem consisting of five Python packages:

| Package | PyPI Link | Role | Standalone? |
|---|---|---|---|
| [`audit-packs`](https://pypi.org/project/audit-packs/) | [pypi](https://pypi.org/project/audit-packs/) | Main CLI & Action entrypoint | **Yes** |
| [`audit-packs-core`](https://pypi.org/project/audit-packs-core/) | [pypi](https://pypi.org/project/audit-packs-core/) | Primitives, diff parsing, normalization | No |
| [`audit-packs-mapping`](https://pypi.org/project/audit-packs-mapping/) | [pypi](https://pypi.org/project/audit-packs-mapping/) | Compliance pack loader & OSCAL exporter | No |
| **`audit-packs-evidence`** | [pypi](https://pypi.org/project/audit-packs-evidence/) | Evidence collectors & heuristic agents | No |
| [`audit-packs-ai`](https://pypi.org/project/audit-packs-ai/) | [pypi](https://pypi.org/project/audit-packs-ai/) | LLM consensus & confidence scoring | No |

---

## 🔗 Related Resources
*   **Main GitHub Repository:** [https://github.com/prakharsingh/audit-packs](https://github.com/prakharsingh/audit-packs)
*   **Documentation & Setup:** [docs/SETUP.md](https://github.com/prakharsingh/audit-packs/blob/main/docs/SETUP.md)
*   **Issue Tracker:** [https://github.com/prakharsingh/audit-packs/issues](https://github.com/prakharsingh/audit-packs/issues)

## 📄 License
This library is licensed under the Apache-2.0 License. See the [LICENSE](https://github.com/prakharsingh/audit-packs/blob/main/LICENSE) file in the main repository for details.
