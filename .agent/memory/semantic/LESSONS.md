# Lessons (auto-distilled + manually curated)

> Entries here outlive specific tasks. The dream cycle promotes recurring
> patterns from episodic into this file. Feel free to curate manually —
> delete bad lessons, tighten wording, reorganize sections.

## Seed lessons
- Always read `protocols/permissions.md` before any destructive tool call.
- Write the failing test before writing the fix.
- Log to episodic memory on every significant action, success or failure.
- When a skill has failed 3+ times in 14 days, propose a rewrite.
- Never force push to protected branches under any circumstance.

## Auto-promoted entries will be appended below

### 2026-06

- Do not define duplicate YAML keys (e.g. metavariable-regex, pattern, pattern-not) as siblings in Semgrep rules; wrap multiple constraints/checks in a 'patterns:' block.  <!-- status=accepted confidence=0.6 evidence=1 id=lesson_bd6036c67c7f -->

### 2026-05

- OpenCode v1.14.48 project-level opencode.json does not accept a top-level 'permissions' key — schema validation rejects it  <!-- status=accepted confidence=0.6 evidence=1 id=lesson_7d477c017118 -->

### 2026-04

- Always serialize timestamps in UTC to avoid cross-region comparison bugs  <!-- status=accepted confidence=0.46 evidence=1 id=lesson_422695ae5b2d -->
