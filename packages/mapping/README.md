# audit-packs-mapping

[![PyPI version](https://img.shields.io/pypi/v/audit-packs-mapping.svg)](https://pypi.org/project/audit-packs-mapping/)
[![Python](https://img.shields.io/pypi/pyversions/audit-packs-mapping.svg)](https://pypi.org/project/audit-packs-mapping/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/prakharsingh/audit-packs/blob/main/LICENSE)
[![GitHub Repository](https://img.shields.io/badge/GitHub-audit--packs-181717?logo=github)](https://github.com/prakharsingh/audit-packs)

<p align="center">
  <img src="https://raw.githubusercontent.com/prakharsingh/audit-packs/main/cover.jpg" alt="Audit-Packs Banner" width="100%" />
</p>

`audit-packs-mapping` is the compliance framework mapping, posture calculation, and OSCAL export engine for the `audit-packs` ecosystem.

> ⚠️ **IMPORTANT: This is a sub-package of the `audit-packs` compliance mapping toolkit. It is NOT designed to be run as a standalone CLI tool.** If you are looking for the main CLI and GitHub Action scanner execution engine, please install and refer to [audit-packs](https://pypi.org/project/audit-packs/).

---

## 📦 Installation

Install this package via `pip` if you are programmatically resolving rules to controls or outputting OSCAL artifacts:

```bash
pip install audit-packs-mapping
```

---

## 🛠️ API Surface & Modules

| Module | Key API Exports | Description |
|---|---|---|
| `audit_packs_mapping.packs` | `load_pack()`, `iter_controls()`, `map_findings()` | Loads YAML pack definitions and maps raw scanner rule IDs to controls. Resolves crosswalk references. |
| `audit_packs_mapping.coverage` | `compute_coverage()` | Calculates posture metrics (pass, fail, manual review) for active frameworks. |
| `audit_packs_mapping.oscal` | `to_assessment_results()` | Serializes mapped findings into standard NIST Open Security Controls Assessment Language (OSCAL) JSON. |

---

## 🏗️ Supported Compliance Frameworks
Framework mappings are maintained as YAML files under `packs/`:

*   **NIST SP 800-53 Rev 5:** The canonical pack (maps Checkov/Semgrep rules to NIST).
*   **Crosswalk Frameworks:** SOC 2, HIPAA, GDPR, ISO/IEC 27001, PCI-DSS, FedRAMP, and Custom Org-Policy (resolve crosswalk rules to underlying NIST controls).

---

## 📦 Ecosystem Architecture

`audit-packs` is built as a modular ecosystem consisting of five Python packages:

| Package | PyPI Link | Role | Standalone? |
|---|---|---|---|
| [`audit-packs`](https://pypi.org/project/audit-packs/) | [pypi](https://pypi.org/project/audit-packs/) | Main CLI & Action entrypoint | **Yes** |
| [`audit-packs-core`](https://pypi.org/project/audit-packs-core/) | [pypi](https://pypi.org/project/audit-packs-core/) | Primitives, diff parsing, normalization | No |
| **`audit-packs-mapping`** | [pypi](https://pypi.org/project/audit-packs-mapping/) | Compliance pack loader & OSCAL exporter | No |
| [`audit-packs-evidence`](https://pypi.org/project/audit-packs-evidence/) | [pypi](https://pypi.org/project/audit-packs-evidence/) | Evidence collectors & heuristic agents | No |
| [`audit-packs-ai`](https://pypi.org/project/audit-packs-ai/) | [pypi](https://pypi.org/project/audit-packs-ai/) | LLM consensus & confidence scoring | No |

---

## 🔗 Related Resources
*   **Main GitHub Repository:** [https://github.com/prakharsingh/audit-packs](https://github.com/prakharsingh/audit-packs)
*   **Documentation & Setup:** [docs/SETUP.md](https://github.com/prakharsingh/audit-packs/blob/main/docs/SETUP.md)
*   **Issue Tracker:** [https://github.com/prakharsingh/audit-packs/issues](https://github.com/prakharsingh/audit-packs/issues)

## 📄 License
This library is licensed under the Apache-2.0 License. See the [LICENSE](https://github.com/prakharsingh/audit-packs/blob/main/LICENSE) file in the main repository for details.
