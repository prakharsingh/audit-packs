# audit-packs-evidence

[![PyPI version](https://img.shields.io/pypi/v/audit-packs-evidence.svg)](https://pypi.org/project/audit-packs-evidence/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../LICENSE)

`audit-packs-evidence` provides the evidence collection, detection agents, and data enrichment capabilities for the `audit-packs` ecosystem. It evaluates code-level syntax and checks workspace configurations to extract context, generate cryptographic evidence paths, and formulate audit-grade evidence details.

## Installation

```bash
pip install audit-packs-evidence
```

## Features

- **Evidence Collector**: Extracts specific code snippets, file context, and line locations associated with scanner findings.
- **Dependency & Config Auditing**: Built-in agents (`Nist80053Agent`, etc.) designed to search configuration files (`requirements.txt`, `pyproject.toml`, `package.json`, `Cargo.toml`, etc.) to locate wildcards, unpinned packages, and out-of-date security configs.
- **Audit Trails**: Structures evidence in clean, human-readable descriptions formatted to fit GRC portals and auditor requests.

## Learn More

This library is part of the larger `audit-packs` Compliance Intelligence Engine. For the main command-line interface, GitHub Action integration, and framework mappings, see the [main repository](https://github.com/prakharsingh/audit-packs).
