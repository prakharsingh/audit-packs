# Audit Packs VS Code Extension

Run `audit-packs` compliance checks directly within your VS Code editor. Get inline compliance error wavy highlights (diagnostics), run complete scans, and initialize compliance configurations from inside your IDE.

## Features

- **Inline Compliance Highlights**: Surfaces compliance violations on the exact file and line where they occur.
- **Run Scan Command**: Trigger a workspace-wide compliance scan manually via `Audit Packs: Run Compliance Scan on Workspace`.
- **Auto-Scan on Save**: Performs a scan in the background when Python, YAML, or Terraform files are saved.
- **Interactive Configuration Bootstrap**: Runs `Audit Packs: Initialize Configuration` to bootstrap your workspace configuration.

## Configuration

You can customize the extension behavior via VS Code Settings:

- `auditPacks.frameworks`: Compliance frameworks to target (comma-separated, default: `nist-800-53,soc2`).
- `auditPacks.scanOnSave`: Enable/disable background checks on file save (default: `true`).
- `auditPacks.failOn`: Minimum severity to register failure (default: `high`).
- `auditPacks.adjudicationMode`: Enable AI adjudication (choices: `off`, `advisory`, `enforce`, default: `off`).

## Installation & Build

To compile and package the extension:

1. Change directory to `packages/vscode-extension`.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Compile typescript:
   ```bash
   npx tsc -p ./
   ```
4. Package the extension:
   ```bash
   npx vsce package
   ```
5. Install the generated `.vsix` file in VS Code.
