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

**Recommended — `pipx`** (isolated venv, always on PATH):
```bash
pipx install audit-packs

# Inject optional scanners into the same venv:
pipx inject audit-packs checkov semgrep
```

Or install into your active Python environment:
```bash
pip install audit-packs
```

Or install editably from source (for contributors):
```bash
# Clone the repository
git clone https://github.com/prakharsingh/audit-packs.git
cd audit-packs

# Install all workspace packages via uv (recommended)
uv sync

# Or via pipx from source
pipx install ./packages/action --force
pipx inject audit-packs ./packages/core ./packages/mapping \
                         ./packages/evidence ./packages/ai --force
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

Run a scan from any git repository. The default Semgrep rules are bundled inside the python package, so the scan runs out-of-the-box using those default rules if no custom path is configured. Missing `--packs-dir` is warned and skipped gracefully:

```bash
# Out-of-the-box run — uses detection agents & bundled default Semgrep rules; pack mapping skips if not configured
audit-packs --frameworks nist-800-53,soc2,gdpr

# Custom run with custom packs and custom Semgrep rules:
audit-packs --frameworks nist-800-53,soc2 \
            --packs-dir ~/projects/audit-packs/packs \
            --rules-path /path/to/my/custom/rules

# Use env vars to avoid repeating flags:
export PACKS_DIR=~/projects/audit-packs/packs
export RULES_PATH=/path/to/my/custom/rules
audit-packs --frameworks nist-800-53,soc2
```

**Dev tip** — add a shell alias:
```bash
alias ap='audit-packs \
  --packs-dir ~/projects/audit-packs/packs \
  --rules-path ~/projects/audit-packs/rules'
```

### Reinstalling after source changes

When you edit a package under `packages/`, reinstall it into the pipx venv:

```bash
# Reinstall only changed packages (fast)
pipx inject audit-packs ./packages/action ./packages/mapping --force

# Reinstall everything
pipx inject audit-packs \
  ./packages/action ./packages/core ./packages/mapping \
  ./packages/evidence ./packages/ai --force

# Full nuke + reinstall
pipx uninstall audit-packs
pipx install ./packages/action --force
pipx inject audit-packs \
  ./packages/core ./packages/mapping ./packages/evidence ./packages/ai --force
```

### Extensible Scanner Plugins
You can run custom scanners using declarative YAML files. Place your scanner configurations under `.audit-packs/scanners/` or custom folders and pass `--scanners-dir`:
```bash
audit-packs --frameworks nist-800-53,soc2 --scanners-dir ./my-scanners --scan-mode full
```

### Framework Pack CLI Utility (`pack`)
You can use the dedicated `pack` subcommand space for framework pack management, validation, testing, publishing, and installation:

* **Initialize a pack**:
  ```bash
  audit-packs pack init <pack-id> [--output-dir packs]
  ```
* **Validate a pack schema**:
  ```bash
  audit-packs pack validate <pack-path>
  ```
* **Dry-run test mapping on test fixtures**:
  ```bash
  audit-packs pack test <pack-path> --fixture <fixture-dir> [--scanners-dir <dir>]
  ```
* **Package/Publish a pack**:
  ```bash
  audit-packs pack publish <pack-path> [--output-dir .]
  ```
* **Install a pack from URL/GitHub**:
  ```bash
  audit-packs pack install <source-url-or-git-repo> [--output-dir <installed-dir>]
  # Examples:
  # audit-packs pack install owner/repo@tag
  # audit-packs pack install https://example.com/custom-pack-1.0.tar.gz
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

## 📦 6. Automatic PyPI Publishing

To automate Python package builds and publication to PyPI, the repository release workflow `.github/workflows/release.yml` publishes the workspace packages using a PyPI API token.

### Triggering the Workflow
Whenever a commit on the `main` branch triggers a new version release via `python-semantic-release`, the workflow automatically:
1. Installs the dependencies and runs the test suite.
2. Generates the version bump commit and tag.
3. Builds the source and wheel distributions for all 5 workspace modules (`audit-packs-core`, `audit-packs-mapping`, `audit-packs-evidence`, `audit-packs-ai`, and `audit-packs`).
4. Publishes all package distributions to PyPI.

### Setup Instructions
Before the publication step can run successfully, you must add your PyPI API token as a repository secret:
1. Generate an API token from your [PyPI Account Settings](https://pypi.org) (with user-wide scope to allow creating the new workspace projects).
2. Add the token as a repository secret named `PYPI_API_TOKEN` in your GitHub repository (**Settings** > **Secrets and variables** > **Actions** > **New repository secret**).

---

## 🔙 Links
- Return to [README.md](../README.md)
