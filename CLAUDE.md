# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## What this project is

**audit-packs** is an open-source GitHub Action that maps IaC security findings to compliance framework controls and posts evidence-backed inline PR review comments with a severity gate.

Architecture: a Python orchestrator delegates detection to OSS engines (Checkov for IaC, Semgrep for authored rules), normalises SARIF output to a common `Finding` model, filters to PR-changed lines only, maps findings to compliance controls via YAML packs, and posts control-tagged PR review comments. The project differentiates on the **control-mapping + evidence UX**, not on building a new analysis engine.

Implementation plan: `docs/superpowers/plans/2026-06-24-audit-packs-mvp.md` (8 TDD tasks; use that as the task guide).

GitHub issues tracking the work: `prakharsingh/audit-packs` issues #1–9.

---

## Key design rules

- **Never re-implement detection logic.** Engines (Checkov, Semgrep) are invoked as subprocesses; findings come back as SARIF.
- **Packs are data, not code.** A framework pack = YAML mapping `(engine, check_id) → control`. NIST 800-53 is the canonical pack; other frameworks (SOC 2, etc.) are crosswalk packs that reference it.
- **Diff-filtered only.** Only findings on lines added/changed in the PR are reported.
- **SARIF is the lingua franca.** All engines emit SARIF; `normalize.py` converts it to the internal `Finding` dataclass before anything else touches the output.
- Severity vocabulary is exactly: `low`, `medium`, `high`, `critical`.
- License: Apache-2.0. No paid-tier engine features (Semgrep Pro, Bearer Pro) may be required.

---

## Development commands

```bash
# Install (once source exists)
pip install -e ".[dev]"

# Run all tests
pytest -v

# Run a single test file
pytest tests/test_packs.py -v

# Run a single test
pytest tests/test_packs.py::test_map_findings_crosswalk_soc2 -v

# Build the Docker action image
docker build -t audit-packs:dev .

# Quick smoke-check engines are on PATH
checkov --version
semgrep --version
```

---

## Code structure (when implemented)

```
src/audit_packs/
  models.py      # Finding + ControlFinding frozen dataclasses; severity_rank()
  diff.py        # parse_unified_diff() → {file: set[line]}
  normalize.py   # sarif_to_findings() — SARIF dict → list[Finding]
  engines.py     # run_checkov() / run_semgrep() — subprocess → SARIF dict
  packs.py       # load_pack(), map_findings() — control mapping + crosswalk
  report.py      # build_comments(), gate_failed(), post_review() — GitHub IO
  cli.py         # analyze() + main() — orchestration entry point

packs/
  nist-800-53.yaml   # canonical: (engine, check_id) → control
  soc2.yaml          # crosswalk: soc2 control → nist-800-53 control ids

rules/
  weak-cipher.yaml   # authored Semgrep rule (hybrid proof: non-Checkov detection)
```

The IO boundary is strict: `engines.py` and `report.py` are the only modules that make subprocess or HTTP calls. Everything between them is pure Python logic testable without network or installed tools.

---

## Agentic-stack brain (`.agent/`)

This repo uses the portable agentic-stack brain. Read at session start (in order):

1. `.agent/AGENTS.md` — full map of the brain
2. `.agent/memory/personal/PREFERENCES.md` — how this user works
3. `.agent/memory/working/REVIEW_QUEUE.md` — pending lessons to review
4. `.agent/memory/semantic/LESSONS.md` — distilled patterns

### Recall before non-trivial actions

For any task involving deploy, migration, schema change, failing test, debug, or refactor:

```bash
python3 .agent/tools/recall.py "<one-line description>"
```

Show output in a `Consulted lessons before acting:` block. If a surfaced lesson conflicts with your intended action, stop and explain why.

### Memory tools

```bash
python3 .agent/tools/show.py               # brain state overview
python3 .agent/tools/learn.py "<rule>" --rationale "<why>"   # teach a new rule
python3 .agent/tools/memory_reflect.py <skill> <action> <outcome> --importance N
```

Log manually after: completing a major feature, any rollback/incident, any architectural decision, any non-obvious project constraint.

### Skills

Read `.agent/skills/_index.md` for discovery. Load a full `SKILL.md` only when its triggers match the current task.

### Hard constraints

- Never force push to `main`, `production`, or `staging`.
- Never delete episodic or semantic memory entries — archive them.
- Never modify `.agent/protocols/permissions.md`.
- Never hand-edit `.agent/memory/semantic/LESSONS.md` — use `graduate.py`.
- Installing new dependencies or modifying CI/CD requires approval (see `.agent/protocols/permissions.md`).
