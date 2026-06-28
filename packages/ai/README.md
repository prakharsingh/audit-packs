# audit-packs-ai

[![PyPI version](https://img.shields.io/pypi/v/audit-packs-ai.svg)](https://pypi.org/project/audit-packs-ai/)
[![Python](https://img.shields.io/pypi/pyversions/audit-packs-ai.svg)](https://pypi.org/project/audit-packs-ai/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/prakharsingh/audit-packs/blob/main/LICENSE)
[![GitHub Repository](https://img.shields.io/badge/GitHub-audit--packs-181717?logo=github)](https://github.com/prakharsingh/audit-packs)

<p align="center">
  <img src="https://raw.githubusercontent.com/prakharsingh/audit-packs/main/cover.jpg" alt="Audit-Packs Banner" width="100%" />
</p>

`audit-packs-ai` provides AI-powered consensus adjudication, composite confidence scoring, and false-positive filtering for the `audit-packs` ecosystem.

> ⚠️ **IMPORTANT: This is a sub-package of the `audit-packs` compliance mapping toolkit. It is NOT designed to be run as a standalone CLI tool.** If you are looking for the main CLI and GitHub Action scanner execution engine, please install and refer to [audit-packs](https://pypi.org/project/audit-packs/).

---

## 📦 Installation

To install this package with core dependencies:
```bash
pip install audit-packs-ai
```

To install with full LLM SDK dependencies (for OpenAI, Anthropic, and Google APIs):
```bash
pip install audit-packs-ai[ai]
```

---

## 🤖 The AI Consensus Ensemble
To resolve the high noise and false-positive rates of typical static security tools, `audit-packs-ai` passes each finding through a multi-agent debate before applying a confidence gate:

1.  **Detector:** Establishes initial compliance relevance and confidence.
2.  **Verifier:** Builds the argument proving the compliance check is violated.
3.  **Adversarial:** Builds the argument defending why this check is a false positive under local configuration context.
4.  **Judge:** Moderates the debate, analyzes the code/environment context, and issues a final consensus confidence score.

---

## 📊 Confidence Scoring Weights
The engine scores compliance findings by weighting six distinct telemetry signals:

| Signal | Weight | Source |
|---|---|---|
| **Rule Confidence** | 20% | Built-in confidence metadata from the static engine rule. |
| **Data-Flow Confidence** | 20% | Flow-sensitivity analysis on variables (source-to-sink). |
| **Model Consensus** | 25% | Final consensus score output by the LLM Judge. |
| **Evidence Confidence** | 15% | Richness and presence of code context and lines. |
| **Control Severity** | 10% | Criticality score of the mapped compliance control. |
| **Historical Precision** | 10% | Long-term precision metrics tracked for the rule ID. |

---

## 🛠️ API Surface & Modules

| Module | Key API Exports | Description |
|---|---|---|
| `audit_packs_ai.adjudicate` | `run_ensemble_adjudication()` | Executes the multi-agent LLM debate routing. |
| `audit_packs_ai.confidence` | `score_finding()`, `apply_confidence_gate()` | Evaluates composite confidence scores and filters findings. |

---

## 📦 Ecosystem Architecture

`audit-packs` is built as a modular ecosystem consisting of five Python packages:

| Package | PyPI Link | Role | Standalone? |
|---|---|---|---|
| [`audit-packs`](https://pypi.org/project/audit-packs/) | [pypi](https://pypi.org/project/audit-packs/) | Main CLI & Action entrypoint | **Yes** |
| [`audit-packs-core`](https://pypi.org/project/audit-packs-core/) | [pypi](https://pypi.org/project/audit-packs-core/) | Primitives, diff parsing, normalization | No |
| [`audit-packs-mapping`](https://pypi.org/project/audit-packs-mapping/) | [pypi](https://pypi.org/project/audit-packs-mapping/) | Compliance pack loader & OSCAL exporter | No |
| [`audit-packs-evidence`](https://pypi.org/project/audit-packs-evidence/) | [pypi](https://pypi.org/project/audit-packs-evidence/) | Evidence collectors & heuristic agents | No |
| **`audit-packs-ai`** | [pypi](https://pypi.org/project/audit-packs-ai/) | LLM consensus & confidence scoring | No |

---

## 🔗 Related Resources
*   **Main GitHub Repository:** [https://github.com/prakharsingh/audit-packs](https://github.com/prakharsingh/audit-packs)
*   **Documentation & Setup:** [docs/SETUP.md](https://github.com/prakharsingh/audit-packs/blob/main/docs/SETUP.md)
*   **Issue Tracker:** [https://github.com/prakharsingh/audit-packs/issues](https://github.com/prakharsingh/audit-packs/issues)

## 📄 License
This library is licensed under the Apache-2.0 License. See the [LICENSE](https://github.com/prakharsingh/audit-packs/blob/main/LICENSE) file in the main repository for details.
