# Contributing to audit-packs

Thank you for your interest in contributing to **audit-packs**! We welcome bug reports, feature suggestions, documentation updates, framework packs, and new rule contributions.

---

## Getting Started

Please read the [Local development](README.md#local-development) section of the README to set up your virtual environment, install development packages, and run the test suite.

### Code Style & Quality Checkpoints

We enforce code quality standards before code can be committed:
- **Pre-commit checks**: We use `pre-commit` to check file formatting, trailing whitespace, and coding standards. Run the checks locally:
  ```bash
  pre-commit run --all-files
  ```
- **Linting & Formatting**: We use `ruff` and `ruff-format` to format code.
- **Test execution**: We use `pytest` for all unit and integration tests. The test suite is automatically executed on a pre-push hook:
  ```bash
  pytest -v
  ```

---

## Contribution Guide

### 1. Adding a Framework Pack

A compliance framework pack maps controls to static check IDs (defined in Checkov, Semgrep, etc.) or Phase 2 detection agents.

1. **Scaffold the YAML Pack**: Create `packs/<framework-id>.yaml` with a `crosswalk: nist-800-53` reference, and a list of controls that map to NIST controls:
   ```yaml
   id: my-framework
   title: My Compliance Framework
   crosswalk: nist-800-53
   controls:
     - { id: MY-CTRL-1, title: Access Management, maps_to: [AC-2] }
   ```
2. **Add Agent Coverage**: If the framework has controls that require custom heuristics or parsing beyond standard engine check IDs, implement a corresponding framework agent in [agents.py](file:///Users/prakhar/projects/audit-packs/src/audit_packs/agents.py) implementing the `DetectionAgent` interface.
3. **Write Tests**: Add appropriate crosswalk and loader checks in [test_packs.py](file:///Users/prakhar/projects/audit-packs/tests/test_packs.py).

### 2. Adding a Semgrep Rule

Custom rules extend detection coverage for patterns engines like Checkov cannot inspect directly.

1. **Author the Rule**: Add the rule YAML file to the `rules/` directory (e.g. `rules/my-new-rule.yaml`).
2. **Map the Rule**: Associate the rule ID with the correct NIST SP 800-53 control in [nist-800-53.yaml](file:///Users/prakhar/projects/audit-packs/packs/nist-800-53.yaml).
3. **Write Tests**: Add a rule test case and verification assertions in [test_rules.py](file:///Users/prakhar/projects/audit-packs/tests/test_rules.py).

---

## Pull Request Guidelines

1. **Conventional Commits**: Ensure commit messages follow the [Conventional Commits](https://www.conventionalcommits.org/) specification (e.g. `feat: ...`, `fix: ...`, `docs: ...`, `chore: ...`).
2. **Atomic Commits**: Group your changes into logical, self-contained commits.
3. **Run Checks**: Verify that all `pre-commit` checks and tests pass locally before pushing.
