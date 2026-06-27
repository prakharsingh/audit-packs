# Audit Packs Compliance Scanner

[![Open VSX](https://img.shields.io/open-vsx/v/prakharsingh/audit-packs-vscode?style=for-the-badge&logo=openvsx)](https://open-vsx.org/extension/prakharsingh/audit-packs-vscode)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](LICENSE)
[![GitHub Repository](https://img.shields.io/badge/GitHub-audit--packs-181717?style=for-the-badge&logo=github)](https://github.com/prakharsingh/audit-packs)

Bring continuous, automated security and compliance checking directly into your developer workspace. **Audit Packs Compliance Scanner** runs local compliance scans on IaC configurations (Terraform, CloudFormation, Kubernetes YAML, etc.) and code, mapping static analysis results directly to standard compliance controls like **NIST SP 800-53**, **SOC 2**, **HIPAA**, **GDPR**, and **FedRAMP**.

<p align="center">
  <img src="https://raw.githubusercontent.com/prakharsingh/audit-packs/main/cover.jpg" alt="Audit Packs VS Code Banner" width="100%" />
</p>

---

## 🔍 Features

*   **Inline Diagnostics & Wave Highlights**: Instantly surfaces compliance violations with VS Code wavy underlines on the exact line and file where the issue is found. Hover over the error to view the rule ID and framework mappings.
*   **Auto-Scan on Save**: Runs checks automatically in the background whenever you save Python, YAML, or Terraform files, ensuring immediate feedback before committing.
*   **Integrated Bootstrap (`--init`) Wizard**: Bootstrap your project configuration directly via the command palette.
*   **Adjudication Integration**: Connects with `audit-packs` AI consensus adjudication engine to filter false positives and surface high-confidence issues.

---

## 🚀 Getting Started

### Prerequisites

The VS Code extension relies on the `audit-packs` CLI tool to run the scans and output SARIF findings. Make sure it is installed and available in your system path (`$PATH`).

```bash
# Install the core audit-packs engine
pip install audit-packs
```

### Installation

#### Open VSX Registry (e.g. VSCodium)
1. Open your editor's **Extensions** view (`Ctrl+Shift+X` or `Cmd+Shift+X`).
2. Search for **Audit Packs Compliance Scanner** and click **Install**.
3. Alternatively, install via command line:
   ```bash
   codium --install-extension prakharsingh.audit-packs-vscode
   ```

#### Local Manual Installation (Recommended for VS Code)
Since the extension is optimized for local environments and source builds:
1. Build and package the extension to a `.vsix` file:
   ```bash
   cd packages/vscode-extension
   npm install && npm run compile && npx vsce package
   ```
2. Install the generated `.vsix` file in VS Code:
   ```bash
   code --install-extension audit-packs-vscode-0.1.0.vsix
   ```

---

## ⚙️ Extension Settings

Customize the extension's behavior by modifying the settings in VS Code Settings (`Ctrl+,` or `Cmd+,`):

| Setting | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `auditPacks.frameworks` | `string` | `"nist-800-53,soc2"` | A comma-separated list of framework pack IDs to target during scans. Supported: `nist-800-53`, `soc2`, `iso27001`, `pci-dss`, `fedramp`, `hipaa`, `gdpr`. |
| `auditPacks.scanOnSave` | `boolean` | `true` | When enabled, runs a background scan whenever a relevant file (Python, YAML, Terraform) is saved. |
| `auditPacks.failOn` | `string` | `"high"` | Minimum finding severity that will flag a scan as failed. Choices: `low`, `medium`, `high`, `critical`. |
| `auditPacks.adjudicationMode` | `string` | `"off"` | AI consensus adjudication mode. Choices: `off` (disabled), `advisory` (score & log findings), `enforce` (suppress findings below confidence threshold). |

---

## 🛠️ Contributed Commands

You can run these commands from the VS Code **Command Palette** (`Ctrl+Shift+P` or `Cmd+Shift+P`):

| Command | Title | Description |
| :--- | :--- | :--- |
| `auditPacks.runScan` | `Audit Packs: Run Compliance Scan on Workspace` | Executes a complete scan of the open workspace and updates inline diagnostics. |
| `auditPacks.init` | `Audit Packs: Initialize Configuration` | Launches the interactive `--init` CLI wizard inside an integrated terminal to bootstrap the workspace configurations. |

---

## 📦 How It Works Under the Hood

1.  **Invocation**: When a scan is triggered (on save or manually), the extension executes the local `audit-packs` CLI command with your configured workspace settings.
2.  **Aggregation**: The CLI invokes configured static analyzers (e.g., Checkov, Semgrep, Trivy, tfsec) and maps findings to compliance controls.
3.  **Reporting**: A unified `audit-packs.sarif` report is generated in your workspace root.
4.  **Diagnostics**: The extension parses the SARIF output, clearing outdated warnings and populating the VS Code diagnostics collection with real-time squigglies.

---

## 🛠️ Build and Package From Source

If you want to compile and install the extension manually:

1.  Clone the repository and change directory to the extension folder:
    ```bash
    cd packages/vscode-extension
    ```
2.  Install dependencies:
    ```bash
    npm install
    ```
3.  Compile the TypeScript code:
    ```bash
    npm run compile
    ```
4.  Package the extension into a `.vsix` file:
    ```bash
    npx vsce package
    ```
5.  Install the generated `.vsix` in VS Code:
    ```bash
    code --install-extension audit-packs-vscode-0.1.0.vsix
    ```

---

## 📄 License

This extension is licensed under the [Apache-2.0 License](LICENSE).
