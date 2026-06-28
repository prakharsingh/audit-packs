# Audit Packs Compliance Scanner

[![Open VSX](https://img.shields.io/open-vsx/v/prakharsingh/audit-packs-vscode?style=for-the-badge&logo=openvsx)](https://open-vsx.org/extension/prakharsingh/audit-packs-vscode)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](https://github.com/prakharsingh/audit-packs/blob/main/LICENSE)
[![GitHub Repository](https://img.shields.io/badge/GitHub-audit--packs-181717?style=for-the-badge&logo=github)](https://github.com/prakharsingh/audit-packs)
[![VS Code Version](https://img.shields.io/badge/VS_Code-v1.80%2B-007ACC?style=for-the-badge&logo=visualstudiocode)](https://github.com/prakharsingh/audit-packs)

<p align="center">
  <img src="https://raw.githubusercontent.com/prakharsingh/audit-packs/main/cover.jpg" alt="Audit Packs VS Code Banner" width="100%" />
</p>

Bring continuous, automated security and compliance checking directly into your developer workspace. **Audit Packs Compliance Scanner** runs local compliance scans on IaC configurations (Terraform, CloudFormation, Kubernetes YAML, etc.) and code, mapping static analysis results directly to standard compliance controls like **NIST SP 800-53**, **SOC 2**, **HIPAA**, **GDPR**, and **FedRAMP**.

---

## 🔍 The Problem
Security scanners identify system vulnerabilities and infrastructure misconfigurations (e.g., public S3 buckets, unpinned packages), but developers are often disconnected from how these issues impact compliance. Researching control details or matching rules to compliance matrices manually is slow and prone to error.

## 💡 The Solution
This extension executes `audit-packs` checks locally, parsing and presenting the findings directly inside VS Code as inline diagnostics (wavy squigglies) on your code. You see exactly which compliance controls are violated and the associated evidence as you code.

---

## ✨ Features

*   **Inline Diagnostics & Highlights:** Surfacing compliance violations with visual wavy underlines directly on the offending code line. Hovering reveals the control ID, rule mapping, and evidence.
*   **Auto-Scan on Save:** Automatically evaluates Python, YAML, and Terraform configurations on save to catch compliance regressions before committing.
*   **Interactive Setup (`--init`):** Bootstrap your configuration file using a CLI wizard run directly from VS Code.
*   **AI Consensus Filter:** Leverages the `audit-packs` AI consensus adjudication engine to filter false-positive scanner alerts.

---

## 📥 Installation

### Prerequisites
The extension executes the `audit-packs` CLI tool to perform local workspace evaluations. Ensure the CLI is installed and available on your system path (`$PATH`):

```bash
pip install audit-packs
```

### Marketplace Installation (Open VSX)
If you use **VSCodium** or a compatible editor:
1.  Open the **Extensions** view (`Ctrl+Shift+X` or `Cmd+Shift+X`).
2.  Search for **Audit Packs Compliance Scanner** and click **Install**.
3.  Alternatively, install via terminal:
    ```bash
    codium --install-extension prakharsingh.audit-packs-vscode
    ```

### Manual VSIX Installation (For VS Code)
Because this extension is published to the Open VSX Registry, if you are using Microsoft VS Code, we recommend building the extension locally and installing the `.vsix` file:

1.  Clone the repository and package the extension:
    ```bash
    git clone https://github.com/prakharsingh/audit-packs.git
    cd audit-packs/packages/vscode-extension
    npm install && npm run compile && npx vsce package
    ```
2.  Install the compiled package:
    ```bash
    code --install-extension audit-packs-vscode-0.1.0.vsix
    ```

---

## ⚙️ Extension Settings

| Setting | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `auditPacks.frameworks` | `string` | `"nist-800-53,soc2"` | Comma-separated list of framework pack IDs to target. Supported: `nist-800-53`, `soc2`, `iso27001`, `pci-dss`, `fedramp`, `hipaa`, `gdpr`. |
| `auditPacks.scanOnSave` | `boolean` | `true` | When enabled, runs background scans automatically whenever a file is saved. |
| `auditPacks.failOn` | `string` | `"high"` | Minimum finding severity to report a scan as failed. Choices: `low`, `medium`, `high`, `critical`. |
| `auditPacks.adjudicationMode` | `string` | `"off"` | AI consensus adjudication mode: `off` (disabled), `advisory` (score findings), or `enforce` (suppress findings below threshold). |

---

## 🛠️ Contributed Commands

You can run these commands from the VS Code **Command Palette** (`Ctrl+Shift+P` or `Cmd+Shift+P`):

| Command | Title | Description |
| :--- | :--- | :--- |
| `auditPacks.runScan` | `Audit Packs: Run Compliance Scan on Workspace` | Scans the workspace and updates inline warnings and problem outputs. |
| `auditPacks.init` | `Audit Packs: Initialize Configuration` | Launches the interactive configuration bootstrapping wizard in the integrated terminal. |

---

## 📦 Related PyPI Packages
This extension interacts with the Python packages of the `audit-packs` ecosystem:

*   [`audit-packs`](https://pypi.org/project/audit-packs/): The main CLI engine.
*   [`audit-packs-core`](https://pypi.org/project/audit-packs-core/): Base primitives and schema models.
*   [`audit-packs-mapping`](https://pypi.org/project/audit-packs-mapping/): Compliance pack mapping logic.
*   [`audit-packs-evidence`](https://pypi.org/project/audit-packs-evidence/): Heuristic detection agents and config audits.
*   [`audit-packs-ai`](https://pypi.org/project/audit-packs-ai/): LLM consensus verification.

---

## 🔗 Project Links & Backtracking
*   **GitHub Repository:** [https://github.com/prakharsingh/audit-packs](https://github.com/prakharsingh/audit-packs)
*   **Issue Tracker:** [https://github.com/prakharsingh/audit-packs/issues](https://github.com/prakharsingh/audit-packs/issues)
*   **Contributing Guidelines:** [CONTRIBUTING.md](https://github.com/prakharsingh/audit-packs/blob/main/CONTRIBUTING.md)

## 📄 License
Licensed under the Apache-2.0 License. See the [LICENSE](https://github.com/prakharsingh/audit-packs/blob/main/LICENSE) file in the main repository.
