# audit-packs-ai

[![PyPI version](https://img.shields.io/pypi/v/audit-packs-ai.svg)](https://pypi.org/project/audit-packs-ai/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../LICENSE)

`audit-packs-ai` implements the AI verification and confidence scoring engine for the `audit-packs` ecosystem. It evaluates finding context using Large Language Models (LLMs) to determine the probability of a finding being a false positive or true positive under the specific organizational configuration.

## Installation

```bash
pip install audit-packs-ai
```

## Features

- **Multi-Provider LLM Integration**: Interfaces with OpenAI, Anthropic, and Google Generative AI (Gemini) APIs.
- **Smart Confidence Scoring**: Calculates confidence levels and generates rationales for each finding to assist developers in prioritizing fixes.
- **False Positive Reduction**: Flags issues that are safe to ignore, reducing noise in security reports.

## Learn More

This library is part of the larger `audit-packs` Compliance Intelligence Engine. For the main command-line interface, GitHub Action integration, and framework mappings, see the [main repository](https://github.com/prakharsingh/audit-packs).
