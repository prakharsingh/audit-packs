# Setup & Integration Guide

Welcome to the comprehensive setup and configuration guide for **audit-packs**.

This document walks you through integrating the compliance engine into your CI pipeline, running it as a standalone local CLI, installing the VS Code extension, and configuring Slack/Jira notifications.

---

## 📋 Prerequisites

Before running `audit-packs`, make sure you have the following installed on your system or runner:

1. **Python 3.11+**
2. **Git**
3. **OSS Scanners** (on your system `PATH`):
   - **Checkov** (`pip install checkov`)
   - **Semgrep** (`pip install semgrep`)
   - **Trivy** (Optional, $\ge$ v0.69.2)
   - **tfsec** (Optional)
   - **gitleaks** (Optional)

---

## 🚀 1. Standalone CLI Setup

To run scans locally on your developer machine:

### Installation
Install the package editably or build from source:
```bash
# Clone the repository
git clone https://github.com/prakharsingh/audit-packs.git
cd audit-packs

# Install using uv (recommended)
uv sync

# Or using pip
pip install -e packages/core -e packages/mapping -e packages/evidence \
            -e packages/ai -e packages/action[ai]
```

### Onboarding Wizard
To bootstrap configuration files in your repository automatically:
```bash
audit-packs --init
```
This wizard will create:
- `audit-models.yaml` (AI router configuration)
- `.github/workflows/audit.yml` (CI configuration)
- `packs/org-policy/controls.yaml` (Custom policy template)

### Local Scanning
Run a full scan on your workspace:
```bash
audit-packs --frameworks nist-800-53,soc2 --scan-mode full
```

### Policy Validation
To validate your custom mapping files or Semgrep rules structures before committing:
```bash
audit-packs --validate-policy
```

---

## 💻 2. VS Code Extension Setup

Catch compliance errors inline as you edit your code:

1. Change directory to `packages/vscode-extension`.
2. Install npm dependencies:
   ```bash
   npm install
   ```
3. Compile the extension code:
   ```bash
   npx tsc -p ./
   ```
4. Package into a `.vsix` installer:
   ```bash
   npx vsce package
   ```
5. Install the generated `.vsix` in VS Code (`Extensions` -> `Install from VSIX...`).

---

## 🔗 3. Slack & Jira Notifications

Send compliance gates and alerts directly to your team communication channels:

### Slack Webhook integration
Provide a Slack Webhook URL to receive rich message blocks:
```bash
audit-packs --slack-webhook "https://hooks.slack.com/services/T00/B00/X00"
```

### Jira Cloud ticket integration
Create compliance failure issues automatically:
```bash
audit-packs --jira-url "https://your-org.atlassian.net" \
            --jira-email "user@your-org.com" \
            --jira-token "your-api-token" \
            --jira-project "SEC"
```

---

## 🖥️ 4. GitHub Actions Setup

To run automatically on Pull Requests, add this to `.github/workflows/audit.yml`:

```yaml
name: Compliance Check
on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write # Required for inline PR reviews
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: prakharsingh/audit-packs@v1
        with:
          frameworks: nist-800-53,soc2
          fail-on: high
```

## 📦 5. Automatic Extension Publishing

To automate compilation, packaging, and publishing of the VS Code extension to the Visual Studio Marketplace and Open VSX Registry, the repository includes a `.github/workflows/publish-extension.yml` workflow.

### Triggering the Workflow
The workflow triggers automatically when a new GitHub **Release** is published (via `python-semantic-release` or manually) or can be run manually using `workflow_dispatch`.

### Configuring Secrets
To enable publishing, you must add the following Repository Secrets in your GitHub repository configuration:
1. `VSCE_PAT`: Your Personal Access Token for the Visual Studio Marketplace (Publisher: `prakharsingh`).
2. `OVSX_PAT`: Your Access Token for the Open VSX Registry.

If these secrets are not configured, the publishing steps will be skipped, allowing the workflow to run safely without failing.

---

## 🔙 Links
- Return to [README.md](../README.md)
