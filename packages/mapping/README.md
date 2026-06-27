# audit-packs-mapping

[![PyPI version](https://img.shields.io/pypi/v/audit-packs-mapping.svg)](https://pypi.org/project/audit-packs-mapping/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../LICENSE)

`audit-packs-mapping` is the compliance framework mapping and coverage calculation engine for the `audit-packs` ecosystem. It evaluates raw security scanner findings and maps them to control requirements in GRC frameworks (such as SOC 2, NIST 800-53, GDPR, HIPAA, and ISO 27001).

## Installation

```bash
pip install audit-packs-mapping
```

## Features

- **Framework Control Mapping**: Resolves raw scanner rule IDs (e.g. Checkov `CKV_AWS_19`, Semgrep rules) to specific compliance controls.
- **Coverage Engine**: Computes compliance pass/fail/manual rates across active control frameworks based on finding states.
- **OSCAL Export**: Generates NIST Open Security Controls Assessment Language (OSCAL) JSON representation of compliance postures.
- **Pack Registry Support**: Loads, validates, and installs compliance packs containing control-to-rule mappings.

## Learn More

This library is part of the larger `audit-packs` Compliance Intelligence Engine. For the main command-line interface, GitHub Action integration, and framework mappings, see the [main repository](https://github.com/prakharsingh/audit-packs).
