# audit-packs-core

[![PyPI version](https://img.shields.io/pypi/v/audit-packs-core.svg)](https://pypi.org/project/audit-packs-core/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../LICENSE)

`audit-packs-core` is the foundational library for the `audit-packs` ecosystem. It provides the core data structures, schema models, parser interfaces, diffing utilities, and normalization primitives used across all other package modules.

## Installation

```bash
pip install audit-packs-core
```

## Features

- **Standardized Schema Models**: Defines standard structures for scanner findings, controls, frameworks, rules, and reports.
- **Normalization Primitives**: Converts scanner-specific findings into a scanner-agnostic intermediate representation.
- **Diffing Utilities**: Compares findings between parent and feature branches to detect newly introduced compliance gaps.
- **YAML Configuration Parser**: Parses standard YAML frameworks and control files.

## Learn More

This library is part of the larger `audit-packs` Compliance Intelligence Engine. For the main command-line interface, GitHub Action integration, and framework mappings, see the [main repository](https://github.com/prakharsingh/audit-packs).
