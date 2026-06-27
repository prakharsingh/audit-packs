# Scanner Coverage Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Trivy (filesystem + image), tfsec, and gitleaks scanners as `BaseEngine` subclasses with curated `packs/nist-800-53/controls.yaml` mappings so their findings flow through the full compliance pipeline.

**Architecture:** Each scanner is a `BaseEngine` subclass in `engines.py`. Its SARIF output flows through the existing `sarif_to_findings → evidence → map_findings` chain unchanged. Pack YAML additions to `packs/nist-800-53/controls.yaml` give findings compliance control attribution; crosswalk packs inherit transitively. Delivery is two PRs: Tasks 1–3 = Trivy (PR 1); Tasks 4–6 = tfsec + gitleaks (PR 2).

**Tech Stack:** Python 3.11, asyncio, pytest 8+, PyYAML 6+, trivy v0.51.1, tfsec v1.28.11, gitleaks v8.18.4

## Global Constraints

- `pytest -v` must pass zero failures after every task.
- New function params `trivy_enabled`, `tfsec_enabled`, `gitleaks_enabled` default to `False` in Python — existing tests call `analyze()`/`assess()` without these kwargs and must keep passing.
- Engine name tags in Python (`"trivy"`, `"tfsec"`, `"gitleaks"`) must match `engine:` keys in pack YAML exactly — the `_canonical_index` lookup is case-sensitive.
- `asyncio.create_subprocess_exec` is the subprocess mechanism — same as existing engines.
- Exit code conventions: Trivy (0 = clean, 1 = findings, ≥2 = error); tfsec (0 = clean, 1 = findings, ≥2 = error); gitleaks (0 = clean, 1 = leaks found, anything not in {0,1} = error).
- Only `engines.py` may make subprocess calls — no new IO boundary exceptions.
- Apache-2.0 license; all new binaries (trivy, tfsec, gitleaks) are open-source.
- Dockerfile scanner versions are pinned and marked for manual update (no Renovate config yet).

---

## Files Created / Modified

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `packages/action/src/audit_packs_action/engines.py` | Add `TrivyEngine`, `TfsecEngine`, `GitleaksEngine` + 4 convenience functions |
| Modify | `packages/action/src/audit_packs_action/cli.py` | Add scanner params to `analyze()`, `assess()`, `main()`; wire async tasks + sync fallback; add findings to pipeline |
| Modify | `packs/nist-800-53/controls.yaml` | Add trivy/tfsec/gitleaks `mappings:` entries and `supported_scanners:` entries to 10 controls |
| Modify | `action.yml` | Add `trivy-enabled`, `trivy-image`, `tfsec-enabled`, `gitleaks-enabled` inputs + env mappings |
| Modify | `Dockerfile` | Add `curl` to apt deps; install trivy, tfsec, gitleaks binaries |
| Create | `tests/test_trivy_engine.py` | TrivyEngine unit tests |
| Create | `tests/test_tfsec_engine.py` | TfsecEngine unit tests |
| Create | `tests/test_gitleaks_engine.py` | GitleaksEngine unit tests |
| Modify | `tests/test_packs.py` | Three new pack-mapping integration tests |

---

## Task 1: TrivyEngine

**Files:**
- Modify: `packages/action/src/audit_packs_action/engines.py`
- Create: `tests/test_trivy_engine.py`

**Interfaces:**
- Produces: `TrivyEngine` class with `name -> "trivy"` and `run_scan_async(target, options) -> dict`
  - `options={}` → filesystem scan: `trivy fs --format sarif --output <tmpfile> <target>`
  - `options={"image": "name:tag"}` → image scan: `trivy image --format sarif --output <tmpfile> name:tag`
- Produces: `run_trivy_fs(target_dir: str) -> dict` convenience function
- Produces: `run_trivy_image(image: str) -> dict` convenience function

- [ ] **Step 1: Create test file with all failing tests**

Create `tests/test_trivy_engine.py`:

```python
import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest

from audit_packs_action.engines import TrivyEngine, run_trivy_fs, run_trivy_image
from audit_packs_core.normalize import sarif_to_findings

_MINIMAL_SARIF = {
    "runs": [
        {
            "tool": {"driver": {"name": "Trivy", "rules": [
                {"id": "AVD-AWS-0132", "shortDescription": {"text": "S3 not encrypted"}}
            ]}},
            "results": [
                {
                    "ruleId": "AVD-AWS-0132",
                    "level": "error",
                    "message": {"text": "Bucket not encrypted"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "main.tf"},
                            "region": {"startLine": 10},
                        }
                    }],
                }
            ],
        }
    ]
}


def _make_proc(returncode: int, stderr: bytes = b""):
    proc = MagicMock()
    proc.returncode = returncode
    async def _comm():
        return b"", stderr
    proc.communicate = _comm
    proc.kill = MagicMock()
    return proc


def _subprocess_writing(sarif: dict, returncode: int = 0):
    """Returns a side_effect coroutine that writes sarif to the --output path."""
    async def _side(*args, **kwargs):
        cmd = list(args)
        try:
            idx = cmd.index("--output")
            with open(cmd[idx + 1], "w") as fh:
                json.dump(sarif, fh)
        except (ValueError, IndexError):
            pass
        return _make_proc(returncode)
    return _side


def test_trivy_fs_returns_sarif():
    engine = TrivyEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_subprocess_writing(_MINIMAL_SARIF)):
        result = engine.run_scan("/tmp/target", {})
    assert result == _MINIMAL_SARIF


def test_trivy_findings_have_engine_trivy():
    engine = TrivyEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_subprocess_writing(_MINIMAL_SARIF)):
        sarif = engine.run_scan("/tmp/target", {})
    findings = sarif_to_findings(sarif, "trivy")
    assert len(findings) == 1
    assert findings[0].engine == "trivy"
    assert findings[0].check_id == "AVD-AWS-0132"


def test_trivy_image_mode_uses_image_subcommand():
    captured = []

    async def _capture(*args, **kwargs):
        captured.extend(args)
        return _make_proc(0)

    engine = TrivyEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_capture):
        engine.run_scan("", {"image": "myapp:latest"})

    assert "image" in captured
    assert "myapp:latest" in captured
    assert "fs" not in captured


def test_trivy_fs_mode_uses_fs_subcommand():
    captured = []

    async def _capture(*args, **kwargs):
        captured.extend(args)
        return _make_proc(0)

    engine = TrivyEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_capture):
        engine.run_scan("/some/path", {})

    assert "fs" in captured
    assert "image" not in captured


def test_trivy_exit_code_1_not_error():
    engine = TrivyEngine()
    with patch("asyncio.create_subprocess_exec",
               side_effect=_subprocess_writing(_MINIMAL_SARIF, returncode=1)):
        result = engine.run_scan("/tmp/target", {})
    assert result == _MINIMAL_SARIF


def test_trivy_exit_code_2_raises():
    async def _bad(*args, **kwargs):
        return _make_proc(2, stderr=b"fatal: db update required")

    engine = TrivyEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_bad):
        with pytest.raises(RuntimeError, match="trivy exited with code 2"):
            engine.run_scan("/tmp/target", {})


def test_trivy_no_output_file_returns_empty():
    async def _no_file(*args, **kwargs):
        return _make_proc(0)

    engine = TrivyEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_no_file):
        result = engine.run_scan("/tmp/target", {})
    assert result == {"runs": []}


def test_run_trivy_fs_convenience():
    with patch("asyncio.create_subprocess_exec",
               side_effect=_subprocess_writing({"runs": []})):
        result = run_trivy_fs("/some/dir")
    assert result == {"runs": []}


def test_run_trivy_image_convenience():
    captured = []

    async def _capture(*args, **kwargs):
        captured.extend(args)
        return _make_proc(0)

    with patch("asyncio.create_subprocess_exec", side_effect=_capture):
        run_trivy_image("myapp:latest")

    assert "image" in captured
    assert "myapp:latest" in captured
```

- [ ] **Step 2: Run tests to verify they all fail**

```bash
cd /Volumes/DevSSD/projects/audit-packs/.claude/worktrees/feature+architectural-alignment
uv run pytest tests/test_trivy_engine.py -v 2>&1 | head -30
```

Expected: `ImportError: cannot import name 'TrivyEngine'` — class does not exist yet.

- [ ] **Step 3: Add TrivyEngine to engines.py**

Append to `packages/action/src/audit_packs_action/engines.py` (after the `run_ast_rules` function at the end of the file):

```python


class TrivyEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "trivy"

    async def run_scan_async(self, target: str, options: dict) -> dict:
        image = options.get("image")
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "trivy.sarif")
            if image:
                cmd = [
                    _resolve_executable("trivy"),
                    "image",
                    "--format",
                    "sarif",
                    "--output",
                    out_file,
                    image,
                ]
            else:
                cmd = [
                    _resolve_executable("trivy"),
                    "fs",
                    "--format",
                    "sarif",
                    "--output",
                    out_file,
                    target,
                ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=_DEFAULT_TIMEOUT
                )
            except asyncio.TimeoutError as exc:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                raise RuntimeError(
                    f"trivy execution timed out after {_DEFAULT_TIMEOUT} seconds"
                ) from exc
            if proc.returncode is not None and proc.returncode >= 2:
                raise RuntimeError(
                    f"trivy exited with code {proc.returncode}: "
                    f"{stderr.decode(errors='replace').strip()}"
                )
            if os.path.exists(out_file):
                try:
                    with open(out_file) as fh:
                        return json.load(fh)
                except json.JSONDecodeError:
                    pass
            return {"runs": []}


def run_trivy_fs(target_dir: str) -> dict:
    return TrivyEngine().run_scan(target_dir, {})


def run_trivy_image(image: str) -> dict:
    return TrivyEngine().run_scan("", {"image": image})
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/test_trivy_engine.py -v
```

Expected: all 9 tests PASS.

- [ ] **Step 5: Run full suite to check for regressions**

```bash
uv run pytest tests/ -v --ignore=tests/test_live_llm.py --ignore=tests/test_real_world_repos.py -q 2>&1 | tail -10
```

Expected: same pass/skip counts as before this task; 0 failures.

- [ ] **Step 6: Commit**

```bash
git add packages/action/src/audit_packs_action/engines.py tests/test_trivy_engine.py
git commit -m "feat: add TrivyEngine (fs + image modes) with unit tests"
```

---

## Task 2: Trivy Pack Mappings

**Files:**
- Modify: `packs/nist-800-53/controls.yaml`
- Modify: `tests/test_packs.py`

**Interfaces:**
- Consumes: `TrivyEngine` (engine name `"trivy"`) from Task 1
- Produces: `map_findings([Finding("AVD-AWS-0132", "trivy", ...)], PACKS, ["nist-800-53"])` returns `[ControlFinding(control_id="SC-28")]`
- Produces: trivy mappings on 8 NIST controls (see table below)

**Verification note:** Run `trivy checks --format json 2>/dev/null | python3 -c "import json,sys; [print(r['id']) for r in json.load(sys.stdin)['checks']]" | grep AVD-AWS | sort | head -30` before writing YAML to confirm rule IDs match the installed Trivy version. IDs below are from the design spec; minor numeric differences across Trivy versions are possible.

- [ ] **Step 1: Add failing pack tests to test_packs.py**

Append to `tests/test_packs.py`:

```python


# --- Trivy mappings ---


def test_trivy_avd_maps_to_sc28():
    cfs = map_findings(
        [Finding("AVD-AWS-0132", "trivy", "main.tf", 5, "high", "msg", "ev")],
        PACKS,
        ["nist-800-53"],
    )
    assert len(cfs) == 1
    assert cfs[0].control_id == "SC-28"


def test_trivy_avd_maps_to_sc7():
    cfs = map_findings(
        [Finding("AVD-AWS-0107", "trivy", "main.tf", 5, "high", "msg", "ev")],
        PACKS,
        ["nist-800-53"],
    )
    assert len(cfs) >= 1
    assert any(cf.control_id == "SC-7" for cf in cfs)


def test_trivy_avd_maps_to_ia5():
    cfs = map_findings(
        [Finding("AVD-AWS-0025", "trivy", "main.tf", 5, "high", "msg", "ev")],
        PACKS,
        ["nist-800-53"],
    )
    assert len(cfs) >= 1
    assert any(cf.control_id == "IA-5" for cf in cfs)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/test_packs.py::test_trivy_avd_maps_to_sc28 tests/test_packs.py::test_trivy_avd_maps_to_sc7 tests/test_packs.py::test_trivy_avd_maps_to_ia5 -v
```

Expected: all 3 FAIL — `AssertionError: assert 0 == 1` (no mappings yet).

- [ ] **Step 3: Add trivy mappings to packs/nist-800-53/controls.yaml**

For each control block listed below, add `- trivy` to its `supported_scanners:` list and add the `mappings:` entries shown. The file already has these controls — locate each by its `id:` field and append to the existing lists.

**SC-5** — no trivy mappings (DoS protection, not a Trivy surface).

**SC-7** (Boundary Protection) — add to `supported_scanners` and `mappings`:
```yaml
  - trivy
```
```yaml
  - engine: trivy
    check_id: AVD-AWS-0107
  - engine: trivy
    check_id: AVD-AWS-0026
  - engine: trivy
    check_id: AVD-AWS-0175
```

**SC-8** (Transmission Confidentiality) — add:
```yaml
  - trivy
```
```yaml
  - engine: trivy
    check_id: AVD-AWS-0020
  - engine: trivy
    check_id: AVD-AWS-0123
```

**SC-12** (Cryptographic Key Management) — add:
```yaml
  - trivy
```
```yaml
  - engine: trivy
    check_id: AVD-AWS-0065
```

**SC-13** (Cryptographic Protection) — add:
```yaml
  - trivy
```
```yaml
  - engine: trivy
    check_id: AVD-AWS-0020
  - engine: trivy
    check_id: AVD-AWS-0123
```

**SC-28** (Protection of Information at Rest) — add:
```yaml
  - trivy
```
```yaml
  - engine: trivy
    check_id: AVD-AWS-0132
  - engine: trivy
    check_id: AVD-AWS-0088
  - engine: trivy
    check_id: AVD-AWS-0178
  - engine: trivy
    check_id: AVD-AWS-0083
  - engine: trivy
    check_id: AVD-AWS-0065
```

**IA-5** (Authenticator Management) — add:
```yaml
  - trivy
```
```yaml
  - engine: trivy
    check_id: AVD-AWS-0025
  - engine: trivy
    check_id: AVD-AWS-0057
```

**AU-2** (Audit Events) — add:
```yaml
  - trivy
```
```yaml
  - engine: trivy
    check_id: AVD-AWS-0001
  - engine: trivy
    check_id: AVD-AWS-0002
```

**CM-7** (Least Functionality) — add:
```yaml
  - trivy
```
```yaml
  - engine: trivy
    check_id: AVD-AWS-0102
```

- [ ] **Step 4: Run pack tests to verify they pass**

```bash
uv run pytest tests/test_packs.py -v
```

Expected: all existing tests plus the 3 new ones PASS.

- [ ] **Step 5: Run full suite to check for regressions**

```bash
uv run pytest tests/ -v --ignore=tests/test_live_llm.py --ignore=tests/test_real_world_repos.py -q 2>&1 | tail -10
```

Expected: 0 failures.

- [ ] **Step 6: Commit**

```bash
git add packs/nist-800-53/controls.yaml tests/test_packs.py
git commit -m "feat: add trivy AVD-* mappings to nist-800-53 pack (8 controls)"
```

---

## Task 3: Trivy CLI Wiring + action.yml + Dockerfile (PR 1)

**Files:**
- Modify: `packages/action/src/audit_packs_action/cli.py`
- Modify: `action.yml`
- Modify: `Dockerfile`

**Interfaces:**
- Consumes: `run_trivy_fs`, `run_trivy_image`, `TrivyEngine` from Task 1
- Produces: `analyze(..., trivy_enabled=False, trivy_image="")` — new optional params
- Produces: `assess(..., trivy_enabled=False, trivy_image="")` — new optional params
- Produces: `main()` reads `TRIVY_ENABLED` (default `"false"`) and `TRIVY_IMAGE` (default `""`) env vars

- [ ] **Step 1: Add trivy imports to cli.py module-level import block**

In `packages/action/src/audit_packs_action/cli.py`, find the existing import block:

```python
from audit_packs_action.engines import (
    run_checkov,
    run_semgrep,
    run_git_diff,
    read_codeql_sarif,
    run_ast_rules,
)
```

Replace with:

```python
from audit_packs_action.engines import (
    run_checkov,
    run_semgrep,
    run_git_diff,
    read_codeql_sarif,
    run_ast_rules,
    run_trivy_fs,
    run_trivy_image,
)
```

- [ ] **Step 2: Add trivy_enabled and trivy_image params to analyze()**

Find the `analyze()` function signature (line ~86):

```python
def analyze(
    repo_dir,
    changed,
    packs_dir,
    rules_path,
    frameworks,
    adj_mode=AdjudicationMode.OFF,
    model_config=None,
    pr_context=None,
    codeql_sarif_dir="",
    precision_data=None,
    weights=None,
    threshold=0.70,
    ast_rules_dir="ast-rules",
):
```

Replace with:

```python
def analyze(
    repo_dir,
    changed,
    packs_dir,
    rules_path,
    frameworks,
    adj_mode=AdjudicationMode.OFF,
    model_config=None,
    pr_context=None,
    codeql_sarif_dir="",
    precision_data=None,
    weights=None,
    threshold=0.70,
    ast_rules_dir="ast-rules",
    trivy_enabled=False,
    trivy_image="",
):
```

- [ ] **Step 3: Update _run_scans_parallel() inside analyze() to add Trivy tasks**

Find the nested `async def _run_scans_parallel():` function inside `analyze()`. Replace it entirely:

```python
    async def _run_scans_parallel():
        import asyncio
        from audit_packs_action.engines import (
            CheckovEngine,
            SemgrepEngine,
            CodeQLEngine,
            ASTEngine,
            TrivyEngine,
        )

        checkov_task = asyncio.create_task(CheckovEngine().run_scan_async(repo_dir, {}))
        semgrep_task = asyncio.create_task(
            SemgrepEngine().run_scan_async(repo_dir, {"rules_path": rules_path})
        )
        if codeql_sarif_dir:
            codeql_task = asyncio.create_task(
                CodeQLEngine().run_scan_async(codeql_sarif_dir, {})
            )
        else:
            codeql_task = None
        ast_task = asyncio.create_task(
            ASTEngine().run_scan_async(repo_dir, {"rules_dir": ast_rules_dir})
        )
        trivy_fs_task = (
            asyncio.create_task(TrivyEngine().run_scan_async(repo_dir, {}))
            if trivy_enabled
            else None
        )
        trivy_img_task = (
            asyncio.create_task(
                TrivyEngine().run_scan_async("", {"image": trivy_image})
            )
            if (trivy_enabled and trivy_image)
            else None
        )

        tasks = [checkov_task, semgrep_task, ast_task]
        if codeql_task:
            tasks.append(codeql_task)
        if trivy_fs_task:
            tasks.append(trivy_fs_task)
        if trivy_img_task:
            tasks.append(trivy_img_task)
        results = await asyncio.gather(*tasks)

        c_sarif = results[0]
        s_sarif = results[1]
        a_sarif = results[2]
        idx = 3
        q_sarif = results[idx] if codeql_task else {"runs": []}
        if codeql_task:
            idx += 1
        t_fs_sarif = results[idx] if trivy_fs_task else {"runs": []}
        if trivy_fs_task:
            idx += 1
        t_img_sarif = results[idx] if trivy_img_task else {"runs": []}

        return c_sarif, s_sarif, q_sarif, a_sarif, t_fs_sarif, t_img_sarif
```

- [ ] **Step 4: Update the asyncio.run() call and sync fallback in analyze()**

Find the block that calls `asyncio.run(_run_scans_parallel())`:

```python
    try:
        import asyncio

        checkov_sarif, semgrep_sarif, codeql_sarif, ast_sarif = asyncio.run(
            _run_scans_parallel()
        )
    except RuntimeError:
        checkov_sarif = run_checkov(repo_dir)
        semgrep_sarif = run_semgrep(repo_dir, rules_path)
        codeql_sarif = (
            read_codeql_sarif(codeql_sarif_dir) if codeql_sarif_dir else {"runs": []}
        )
        ast_sarif = run_ast_rules(repo_dir, ast_rules_dir)
```

Replace with:

```python
    try:
        import asyncio

        (
            checkov_sarif,
            semgrep_sarif,
            codeql_sarif,
            ast_sarif,
            trivy_fs_sarif,
            trivy_img_sarif,
        ) = asyncio.run(_run_scans_parallel())
    except RuntimeError:
        checkov_sarif = run_checkov(repo_dir)
        semgrep_sarif = run_semgrep(repo_dir, rules_path)
        codeql_sarif = (
            read_codeql_sarif(codeql_sarif_dir) if codeql_sarif_dir else {"runs": []}
        )
        ast_sarif = run_ast_rules(repo_dir, ast_rules_dir)
        trivy_fs_sarif = run_trivy_fs(repo_dir) if trivy_enabled else {"runs": []}
        trivy_img_sarif = (
            run_trivy_image(trivy_image)
            if (trivy_enabled and trivy_image)
            else {"runs": []}
        )
```

- [ ] **Step 5: Add Trivy findings to analyze() pipeline**

Find the findings assembly block in `analyze()`:

```python
    findings = []
    findings += sarif_to_findings(checkov_sarif, "checkov")
    findings += sarif_to_findings(semgrep_sarif, "semgrep")
    findings += sarif_to_findings(codeql_sarif, "codeql")
    findings += sarif_to_findings(ast_sarif, "ast")
```

Replace with:

```python
    findings = []
    findings += sarif_to_findings(checkov_sarif, "checkov")
    findings += sarif_to_findings(semgrep_sarif, "semgrep")
    findings += sarif_to_findings(codeql_sarif, "codeql")
    findings += sarif_to_findings(ast_sarif, "ast")
    trivy_runs = trivy_fs_sarif.get("runs", []) + trivy_img_sarif.get("runs", [])
    if trivy_runs:
        merged_trivy = {"runs": trivy_runs}
        rule_confidences.update(extract_rule_confidences(merged_trivy, "trivy"))
        findings += sarif_to_findings(merged_trivy, "trivy")
```

Also add `rule_confidences` update for trivy near the other `extract_rule_confidences` calls. Find the block:

```python
    rule_confidences: dict[str, float] = {}
    rule_confidences.update(extract_rule_confidences(semgrep_sarif, "semgrep"))
    rule_confidences.update(extract_rule_confidences(codeql_sarif, "codeql"))
    rule_confidences.update(extract_rule_confidences(ast_sarif, "ast"))
```

The `rule_confidences.update` for trivy is already handled in the findings block above (only if `trivy_runs` is non-empty), so no change needed here.

- [ ] **Step 6: Add trivy_enabled and trivy_image params to assess()**

Find the `assess()` function signature (line ~288):

```python
def assess(
    repo_dir,
    packs_dir,
    rules_path,
    frameworks,
    adj_mode=AdjudicationMode.OFF,
    model_config=None,
    precision_data=None,
    weights=None,
    threshold=0.70,
    codeql_sarif_dir="",
    ast_rules_dir="ast-rules",
):
```

Replace with:

```python
def assess(
    repo_dir,
    packs_dir,
    rules_path,
    frameworks,
    adj_mode=AdjudicationMode.OFF,
    model_config=None,
    precision_data=None,
    weights=None,
    threshold=0.70,
    codeql_sarif_dir="",
    ast_rules_dir="ast-rules",
    trivy_enabled=False,
    trivy_image="",
):
```

- [ ] **Step 7: Update _run_scans_parallel_assess() inside assess()**

Find the nested `async def _run_scans_parallel_assess():` and replace it:

```python
    async def _run_scans_parallel_assess():
        import asyncio
        from audit_packs_action.engines import (
            CheckovEngine,
            SemgrepEngine,
            ASTEngine,
            TrivyEngine,
        )

        checkov_task = asyncio.create_task(CheckovEngine().run_scan_async(repo_dir, {}))
        semgrep_task = asyncio.create_task(
            SemgrepEngine().run_scan_async(repo_dir, {"rules_path": rules_path})
        )
        ast_task = asyncio.create_task(
            ASTEngine().run_scan_async(repo_dir, {"rules_dir": ast_rules_dir})
        )
        trivy_fs_task = (
            asyncio.create_task(TrivyEngine().run_scan_async(repo_dir, {}))
            if trivy_enabled
            else None
        )
        trivy_img_task = (
            asyncio.create_task(
                TrivyEngine().run_scan_async("", {"image": trivy_image})
            )
            if (trivy_enabled and trivy_image)
            else None
        )

        tasks = [checkov_task, semgrep_task, ast_task]
        if trivy_fs_task:
            tasks.append(trivy_fs_task)
        if trivy_img_task:
            tasks.append(trivy_img_task)
        results = await asyncio.gather(*tasks)

        c_sarif, s_sarif, a_sarif = results[0], results[1], results[2]
        idx = 3
        t_fs = results[idx] if trivy_fs_task else {"runs": []}
        if trivy_fs_task:
            idx += 1
        t_img = results[idx] if trivy_img_task else {"runs": []}

        return c_sarif, s_sarif, a_sarif, t_fs, t_img
```

- [ ] **Step 8: Update asyncio.run() call and sync fallback in assess()**

Find:

```python
    try:
        import asyncio

        checkov_sarif, semgrep_sarif, ast_sarif = asyncio.run(
            _run_scans_parallel_assess()
        )
    except RuntimeError:
        checkov_sarif = run_checkov(repo_dir)
        semgrep_sarif = run_semgrep(repo_dir, rules_path)
        ast_sarif = run_ast_rules(repo_dir, ast_rules_dir)
```

Replace with:

```python
    try:
        import asyncio

        (
            checkov_sarif,
            semgrep_sarif,
            ast_sarif,
            trivy_fs_sarif,
            trivy_img_sarif,
        ) = asyncio.run(_run_scans_parallel_assess())
    except RuntimeError:
        checkov_sarif = run_checkov(repo_dir)
        semgrep_sarif = run_semgrep(repo_dir, rules_path)
        ast_sarif = run_ast_rules(repo_dir, ast_rules_dir)
        trivy_fs_sarif = run_trivy_fs(repo_dir) if trivy_enabled else {"runs": []}
        trivy_img_sarif = (
            run_trivy_image(trivy_image)
            if (trivy_enabled and trivy_image)
            else {"runs": []}
        )
```

- [ ] **Step 9: Add Trivy findings to assess() pipeline**

Find the findings assembly block in `assess()`:

```python
    findings = []
    findings += sarif_to_findings(checkov_sarif, "checkov")
    findings += sarif_to_findings(semgrep_sarif, "semgrep")
    findings += sarif_to_findings(codeql_sarif, "codeql")
    findings += sarif_to_findings(ast_sarif, "ast")
```

Replace with:

```python
    findings = []
    findings += sarif_to_findings(checkov_sarif, "checkov")
    findings += sarif_to_findings(semgrep_sarif, "semgrep")
    findings += sarif_to_findings(codeql_sarif, "codeql")
    findings += sarif_to_findings(ast_sarif, "ast")
    trivy_runs = trivy_fs_sarif.get("runs", []) + trivy_img_sarif.get("runs", [])
    if trivy_runs:
        merged_trivy = {"runs": trivy_runs}
        rule_confidences.update(extract_rule_confidences(merged_trivy, "trivy"))
        findings += sarif_to_findings(merged_trivy, "trivy")
```

- [ ] **Step 10: Add env var reads and pass to analyze()/assess() in main()**

In `main()`, find the block that reads `ast_rules_dir` (around line 547):

```python
    codeql_sarif_dir = os.environ.get("CODEQL_SARIF_DIR", "")
    ast_rules_dir = os.environ.get("AST_RULES_DIR", "ast-rules")
    if not os.path.isabs(ast_rules_dir):
        ast_rules_dir = os.path.join(workspace, ast_rules_dir)
```

Add immediately after:

```python
    trivy_enabled = os.environ.get("TRIVY_ENABLED", "false").lower() == "true"
    trivy_image = os.environ.get("TRIVY_IMAGE", "")
```

Find the `analyze(...)` call in `main()` and add the new kwargs:

```python
        scored = analyze(
            workspace,
            changed,
            packs_dir,
            rules_path,
            frameworks,
            adj_mode=adj_mode,
            model_config=model_config,
            pr_context=pr_context,
            codeql_sarif_dir=codeql_sarif_dir,
            precision_data=precision_data,
            weights=weights,
            threshold=threshold,
            ast_rules_dir=ast_rules_dir,
            trivy_enabled=trivy_enabled,
            trivy_image=trivy_image,
        )
```

Find the `assess(...)` call in `main()` and add the new kwargs:

```python
        control_statuses = assess(
            workspace,
            packs_dir,
            rules_path,
            frameworks,
            adj_mode=adj_mode,
            model_config=model_config,
            precision_data=precision_data,
            weights=weights,
            threshold=threshold,
            codeql_sarif_dir=codeql_sarif_dir,
            ast_rules_dir=ast_rules_dir,
            trivy_enabled=trivy_enabled,
            trivy_image=trivy_image,
        )
```

- [ ] **Step 11: Add Trivy inputs to action.yml**

In `action.yml`, after the `ast-rules:` input block (around line 61), add:

```yaml
  trivy-enabled:
    description: "Run Trivy filesystem scan for IaC misconfigs (container image scan also via trivy-image)"
    default: "true"

  trivy-image:
    description: "Docker image tag to scan with Trivy (e.g. myapp:latest). Empty = skip image scan."
    default: ""
```

In the `env:` section under `runs:`, after the `AST_RULES_DIR:` line, add:

```yaml
    TRIVY_ENABLED:    ${{ inputs.trivy-enabled }}
    TRIVY_IMAGE:      ${{ inputs.trivy-image }}
```

- [ ] **Step 12: Update Dockerfile to install curl and trivy**

Find the existing apt-get line in `Dockerfile`:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
```

Replace with:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends git curl && rm -rf /var/lib/apt/lists/*
```

After the `pip install` block (after line 15 in the original), add:

```dockerfile
# trivy v0.51.1 — bump version here to upgrade
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin v0.51.1
```

- [ ] **Step 13: Run full suite**

```bash
uv run pytest tests/ -v --ignore=tests/test_live_llm.py --ignore=tests/test_real_world_repos.py -q 2>&1 | tail -10
```

Expected: 0 failures.

- [ ] **Step 14: Commit (PR 1 ready)**

```bash
git add packages/action/src/audit_packs_action/cli.py action.yml Dockerfile
git commit -m "feat: wire Trivy into analyze/assess pipeline and action.yml (PR 1)"
```

---

## Task 4: TfsecEngine + GitleaksEngine

**Files:**
- Modify: `packages/action/src/audit_packs_action/engines.py`
- Create: `tests/test_tfsec_engine.py`
- Create: `tests/test_gitleaks_engine.py`

**Interfaces:**
- Produces: `TfsecEngine` with `name -> "tfsec"`, `run_scan_async(target, options={}) -> dict`
  - Command: `tfsec --format sarif --out <tmpfile> <target>`
- Produces: `run_tfsec(target_dir: str) -> dict`
- Produces: `GitleaksEngine` with `name -> "gitleaks"`, `run_scan_async(target, options={}) -> dict`
  - Command: `gitleaks detect --report-format sarif --report-path <tmpfile> --source <target> --no-git`
  - Exit codes: 0 = clean, 1 = leaks found (not an error), anything else = RuntimeError
- Produces: `run_gitleaks(target_dir: str) -> dict`

- [ ] **Step 1: Create test_tfsec_engine.py**

```python
import json
from unittest.mock import MagicMock, patch

import pytest

from audit_packs_action.engines import TfsecEngine, run_tfsec
from audit_packs_core.normalize import sarif_to_findings

_TFSEC_SARIF = {
    "runs": [
        {
            "tool": {"driver": {"name": "tfsec", "rules": [
                {"id": "aws-s3-enable-bucket-encryption",
                 "shortDescription": {"text": "S3 encryption disabled"}}
            ]}},
            "results": [
                {
                    "ruleId": "aws-s3-enable-bucket-encryption",
                    "level": "error",
                    "message": {"text": "Bucket has no encryption"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "main.tf"},
                            "region": {"startLine": 3},
                        }
                    }],
                }
            ],
        }
    ]
}


def _make_proc(returncode: int, stderr: bytes = b""):
    proc = MagicMock()
    proc.returncode = returncode
    async def _comm():
        return b"", stderr
    proc.communicate = _comm
    proc.kill = MagicMock()
    return proc


def _subprocess_writing(sarif: dict, returncode: int = 0):
    async def _side(*args, **kwargs):
        cmd = list(args)
        try:
            idx = cmd.index("--out")
            with open(cmd[idx + 1], "w") as fh:
                json.dump(sarif, fh)
        except (ValueError, IndexError):
            pass
        return _make_proc(returncode)
    return _side


def test_tfsec_returns_sarif():
    engine = TfsecEngine()
    with patch("asyncio.create_subprocess_exec",
               side_effect=_subprocess_writing(_TFSEC_SARIF)):
        result = engine.run_scan("/tmp/target", {})
    assert result == _TFSEC_SARIF


def test_tfsec_findings_have_engine_tfsec():
    engine = TfsecEngine()
    with patch("asyncio.create_subprocess_exec",
               side_effect=_subprocess_writing(_TFSEC_SARIF)):
        sarif = engine.run_scan("/tmp/target", {})
    findings = sarif_to_findings(sarif, "tfsec")
    assert len(findings) == 1
    assert findings[0].engine == "tfsec"
    assert findings[0].check_id == "aws-s3-enable-bucket-encryption"


def test_tfsec_exit_code_1_not_error():
    engine = TfsecEngine()
    with patch("asyncio.create_subprocess_exec",
               side_effect=_subprocess_writing(_TFSEC_SARIF, returncode=1)):
        result = engine.run_scan("/tmp/target", {})
    assert result == _TFSEC_SARIF


def test_tfsec_exit_code_2_raises():
    async def _bad(*args, **kwargs):
        return _make_proc(2, stderr=b"panic: nil pointer")

    engine = TfsecEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_bad):
        with pytest.raises(RuntimeError, match="tfsec exited with code 2"):
            engine.run_scan("/tmp/target", {})


def test_tfsec_no_output_file_returns_empty():
    async def _no_file(*args, **kwargs):
        return _make_proc(0)

    engine = TfsecEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_no_file):
        result = engine.run_scan("/tmp/target", {})
    assert result == {"runs": []}


def test_run_tfsec_convenience():
    with patch("asyncio.create_subprocess_exec",
               side_effect=_subprocess_writing({"runs": []})):
        result = run_tfsec("/some/dir")
    assert result == {"runs": []}
```

- [ ] **Step 2: Create test_gitleaks_engine.py**

```python
import json
from unittest.mock import MagicMock, patch

import pytest

from audit_packs_action.engines import GitleaksEngine, run_gitleaks
from audit_packs_core.normalize import sarif_to_findings

_GITLEAKS_SARIF = {
    "runs": [
        {
            "tool": {"driver": {"name": "gitleaks", "rules": [
                {"id": "aws-access-token",
                 "shortDescription": {"text": "AWS Access Token detected"}}
            ]}},
            "results": [
                {
                    "ruleId": "aws-access-token",
                    "level": "error",
                    "message": {"text": "AWS Access Key found"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "config.py"},
                            "region": {"startLine": 7},
                        }
                    }],
                }
            ],
        }
    ]
}


def _make_proc(returncode: int, stderr: bytes = b""):
    proc = MagicMock()
    proc.returncode = returncode
    async def _comm():
        return b"", stderr
    proc.communicate = _comm
    proc.kill = MagicMock()
    return proc


def _subprocess_writing(sarif: dict, returncode: int = 0):
    async def _side(*args, **kwargs):
        cmd = list(args)
        try:
            idx = cmd.index("--report-path")
            with open(cmd[idx + 1], "w") as fh:
                json.dump(sarif, fh)
        except (ValueError, IndexError):
            pass
        return _make_proc(returncode)
    return _side


def test_gitleaks_returns_sarif():
    engine = GitleaksEngine()
    with patch("asyncio.create_subprocess_exec",
               side_effect=_subprocess_writing(_GITLEAKS_SARIF)):
        result = engine.run_scan("/tmp/target", {})
    assert result == _GITLEAKS_SARIF


def test_gitleaks_findings_have_engine_gitleaks():
    engine = GitleaksEngine()
    with patch("asyncio.create_subprocess_exec",
               side_effect=_subprocess_writing(_GITLEAKS_SARIF)):
        sarif = engine.run_scan("/tmp/target", {})
    findings = sarif_to_findings(sarif, "gitleaks")
    assert len(findings) == 1
    assert findings[0].engine == "gitleaks"
    assert findings[0].check_id == "aws-access-token"


def test_gitleaks_exit_code_1_not_error():
    """Exit code 1 = leaks found; not an error."""
    engine = GitleaksEngine()
    with patch("asyncio.create_subprocess_exec",
               side_effect=_subprocess_writing(_GITLEAKS_SARIF, returncode=1)):
        result = engine.run_scan("/tmp/target", {})
    assert result == _GITLEAKS_SARIF


def test_gitleaks_exit_code_126_raises():
    """Exit codes not in {0, 1} are errors."""
    async def _bad(*args, **kwargs):
        return _make_proc(126, stderr=b"exec format error")

    engine = GitleaksEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_bad):
        with pytest.raises(RuntimeError, match="gitleaks exited with code 126"):
            engine.run_scan("/tmp/target", {})


def test_gitleaks_uses_no_git_flag():
    captured = []

    async def _capture(*args, **kwargs):
        captured.extend(args)
        return _make_proc(0)

    engine = GitleaksEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_capture):
        engine.run_scan("/tmp/target", {})

    assert "--no-git" in captured


def test_gitleaks_no_output_file_returns_empty():
    async def _no_file(*args, **kwargs):
        return _make_proc(0)

    engine = GitleaksEngine()
    with patch("asyncio.create_subprocess_exec", side_effect=_no_file):
        result = engine.run_scan("/tmp/target", {})
    assert result == {"runs": []}


def test_run_gitleaks_convenience():
    with patch("asyncio.create_subprocess_exec",
               side_effect=_subprocess_writing({"runs": []})):
        result = run_gitleaks("/some/dir")
    assert result == {"runs": []}
```

- [ ] **Step 3: Run both test files to verify they fail**

```bash
uv run pytest tests/test_tfsec_engine.py tests/test_gitleaks_engine.py -v 2>&1 | head -20
```

Expected: `ImportError: cannot import name 'TfsecEngine'` and `ImportError: cannot import name 'GitleaksEngine'`.

- [ ] **Step 4: Add TfsecEngine and GitleaksEngine to engines.py**

Append to `packages/action/src/audit_packs_action/engines.py` (after the `run_trivy_image` function):

```python


class TfsecEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "tfsec"

    async def run_scan_async(self, target: str, options: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "tfsec.sarif")
            cmd = [
                _resolve_executable("tfsec"),
                "--format",
                "sarif",
                "--out",
                out_file,
                target,
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=_DEFAULT_TIMEOUT
                )
            except asyncio.TimeoutError as exc:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                raise RuntimeError(
                    f"tfsec execution timed out after {_DEFAULT_TIMEOUT} seconds"
                ) from exc
            if proc.returncode is not None and proc.returncode >= 2:
                raise RuntimeError(
                    f"tfsec exited with code {proc.returncode}: "
                    f"{stderr.decode(errors='replace').strip()}"
                )
            if os.path.exists(out_file):
                try:
                    with open(out_file) as fh:
                        return json.load(fh)
                except json.JSONDecodeError:
                    pass
            return {"runs": []}


def run_tfsec(target_dir: str) -> dict:
    return TfsecEngine().run_scan(target_dir, {})


class GitleaksEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "gitleaks"

    async def run_scan_async(self, target: str, options: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "gitleaks.sarif")
            cmd = [
                _resolve_executable("gitleaks"),
                "detect",
                "--report-format",
                "sarif",
                "--report-path",
                out_file,
                "--source",
                target,
                "--no-git",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=_DEFAULT_TIMEOUT
                )
            except asyncio.TimeoutError as exc:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                raise RuntimeError(
                    f"gitleaks execution timed out after {_DEFAULT_TIMEOUT} seconds"
                ) from exc
            if proc.returncode is not None and proc.returncode not in (0, 1):
                raise RuntimeError(
                    f"gitleaks exited with code {proc.returncode}: "
                    f"{stderr.decode(errors='replace').strip()}"
                )
            if os.path.exists(out_file):
                try:
                    with open(out_file) as fh:
                        return json.load(fh)
                except json.JSONDecodeError:
                    pass
            return {"runs": []}


def run_gitleaks(target_dir: str) -> dict:
    return GitleaksEngine().run_scan(target_dir, {})
```

- [ ] **Step 5: Run both test files to verify they pass**

```bash
uv run pytest tests/test_tfsec_engine.py tests/test_gitleaks_engine.py -v
```

Expected: all 13 tests PASS.

- [ ] **Step 6: Run full suite to check for regressions**

```bash
uv run pytest tests/ -v --ignore=tests/test_live_llm.py --ignore=tests/test_real_world_repos.py -q 2>&1 | tail -10
```

Expected: 0 failures.

- [ ] **Step 7: Commit**

```bash
git add packages/action/src/audit_packs_action/engines.py tests/test_tfsec_engine.py tests/test_gitleaks_engine.py
git commit -m "feat: add TfsecEngine and GitleaksEngine with unit tests"
```

---

## Task 5: tfsec + gitleaks Pack Mappings

**Files:**
- Modify: `packs/nist-800-53/controls.yaml`
- Modify: `tests/test_packs.py`

**Interfaces:**
- Consumes: `TfsecEngine` (engine name `"tfsec"`) and `GitleaksEngine` (engine name `"gitleaks"`) from Task 4
- Produces: tfsec mappings on 8 NIST controls; gitleaks mappings on IA-5 and SC-13

- [ ] **Step 1: Add failing pack tests for tfsec and gitleaks**

Append to `tests/test_packs.py`:

```python


# --- tfsec mappings ---


def test_tfsec_s3_encryption_maps_to_sc28():
    cfs = map_findings(
        [Finding("aws-s3-enable-bucket-encryption", "tfsec", "main.tf", 3, "high", "msg", "ev")],
        PACKS,
        ["nist-800-53"],
    )
    assert len(cfs) >= 1
    assert any(cf.control_id == "SC-28" for cf in cfs)


def test_tfsec_iam_no_root_maps_to_ac6():
    cfs = map_findings(
        [Finding("aws-iam-no-root-usage", "tfsec", "main.tf", 1, "critical", "msg", "ev")],
        PACKS,
        ["nist-800-53"],
    )
    assert len(cfs) >= 1
    assert any(cf.control_id == "AC-6" for cf in cfs)


def test_tfsec_secrets_maps_to_ia5():
    cfs = map_findings(
        [Finding("general-secrets-no-plaintext-exposure", "tfsec", "main.tf", 5, "high", "msg", "ev")],
        PACKS,
        ["nist-800-53"],
    )
    assert len(cfs) >= 1
    assert any(cf.control_id == "IA-5" for cf in cfs)


# --- gitleaks mappings ---


def test_gitleaks_aws_key_maps_to_ia5():
    cfs = map_findings(
        [Finding("aws-access-token", "gitleaks", "config.py", 7, "critical", "msg", "ev")],
        PACKS,
        ["nist-800-53"],
    )
    assert len(cfs) >= 1
    assert any(cf.control_id == "IA-5" for cf in cfs)


def test_gitleaks_private_key_maps_to_ia5_and_sc13():
    cfs = map_findings(
        [Finding("private-key", "gitleaks", "config.py", 2, "critical", "msg", "ev")],
        PACKS,
        ["nist-800-53"],
    )
    control_ids = {cf.control_id for cf in cfs}
    assert "IA-5" in control_ids
    assert "SC-13" in control_ids
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/test_packs.py::test_tfsec_s3_encryption_maps_to_sc28 tests/test_packs.py::test_tfsec_iam_no_root_maps_to_ac6 tests/test_packs.py::test_tfsec_secrets_maps_to_ia5 tests/test_packs.py::test_gitleaks_aws_key_maps_to_ia5 tests/test_packs.py::test_gitleaks_private_key_maps_to_ia5_and_sc13 -v
```

Expected: all 5 FAIL.

- [ ] **Step 3: Add tfsec mappings to packs/nist-800-53/controls.yaml**

For each control, add `- tfsec` to `supported_scanners:` and the `mappings:` entries shown.

**SC-7** (Boundary Protection) — add:
```yaml
  - tfsec
```
```yaml
  - engine: tfsec
    check_id: aws-ec2-no-public-ip-subnet
  - engine: tfsec
    check_id: aws-s3-no-public-buckets
  - engine: tfsec
    check_id: aws-s3-no-public-access-with-acl
```

**SC-12** (Cryptographic Key Management) — add:
```yaml
  - tfsec
```
```yaml
  - engine: tfsec
    check_id: aws-kms-auto-rotate-keys
```

**SC-28** (Protection of Information at Rest) — add:
```yaml
  - tfsec
```
```yaml
  - engine: tfsec
    check_id: aws-s3-enable-bucket-encryption
  - engine: tfsec
    check_id: aws-rds-encrypt-cluster-storage-data
  - engine: tfsec
    check_id: aws-ebs-enable-volume-encryption
```

**IA-2** (Identification and Authentication) — add:
```yaml
  - tfsec
```
```yaml
  - engine: tfsec
    check_id: aws-iam-enforce-mfa
```

**IA-5** (Authenticator Management) — add:
```yaml
  - tfsec
  - gitleaks
```
```yaml
  - engine: tfsec
    check_id: general-secrets-no-plaintext-exposure
  - engine: tfsec
    check_id: aws-ecs-no-plaintext-exposed-creds
  - engine: gitleaks
    check_id: aws-access-token
  - engine: gitleaks
    check_id: github-pat
  - engine: gitleaks
    check_id: github-oauth
  - engine: gitleaks
    check_id: github-app-token
  - engine: gitleaks
    check_id: github-fine-grained-pat
  - engine: gitleaks
    check_id: slack-bot-token
  - engine: gitleaks
    check_id: slack-user-token
  - engine: gitleaks
    check_id: slack-webhook-url
  - engine: gitleaks
    check_id: stripe-access-token
  - engine: gitleaks
    check_id: stripe-restricted-key
  - engine: gitleaks
    check_id: google-api-key
  - engine: gitleaks
    check_id: google-oauth
  - engine: gitleaks
    check_id: heroku-api-key
  - engine: gitleaks
    check_id: twilio-api-key
  - engine: gitleaks
    check_id: generic-api-key
  - engine: gitleaks
    check_id: private-key
```

**SC-13** (Cryptographic Protection) — add:
```yaml
  - gitleaks
```
```yaml
  - engine: gitleaks
    check_id: private-key
```

**AC-6** (Least Privilege) — add:
```yaml
  - tfsec
```
```yaml
  - engine: tfsec
    check_id: aws-iam-no-root-usage
  - engine: tfsec
    check_id: aws-iam-no-user-attached-policies
```

**AU-2** (Audit Events) — add:
```yaml
  - tfsec
```
```yaml
  - engine: tfsec
    check_id: aws-cloudtrail-enable-all-regions
  - engine: tfsec
    check_id: aws-eks-enable-control-plane-logging
```

**AU-3** (Content of Audit Records) — add:
```yaml
  - tfsec
```
```yaml
  - engine: tfsec
    check_id: aws-lambda-enable-tracing
```

- [ ] **Step 4: Run pack tests to verify they pass**

```bash
uv run pytest tests/test_packs.py -v
```

Expected: all tests PASS.

- [ ] **Step 5: Run full suite**

```bash
uv run pytest tests/ -v --ignore=tests/test_live_llm.py --ignore=tests/test_real_world_repos.py -q 2>&1 | tail -10
```

Expected: 0 failures.

- [ ] **Step 6: Commit**

```bash
git add packs/nist-800-53/controls.yaml tests/test_packs.py
git commit -m "feat: add tfsec and gitleaks mappings to nist-800-53 pack (8 controls)"
```

---

## Task 6: tfsec + gitleaks CLI Wiring + action.yml + Dockerfile (PR 2)

**Files:**
- Modify: `packages/action/src/audit_packs_action/cli.py`
- Modify: `action.yml`
- Modify: `Dockerfile`

**Interfaces:**
- Consumes: `run_tfsec`, `run_gitleaks`, `TfsecEngine`, `GitleaksEngine` from Task 4
- Produces: `analyze(..., tfsec_enabled=False, gitleaks_enabled=False)` — new optional params
- Produces: `assess(..., tfsec_enabled=False, gitleaks_enabled=False)` — new optional params
- Produces: `main()` reads `TFSEC_ENABLED` (default `"false"`) and `GITLEAKS_ENABLED` (default `"false"`) env vars

- [ ] **Step 1: Add tfsec and gitleaks to cli.py module-level imports**

Find the import block (updated in Task 3):

```python
from audit_packs_action.engines import (
    run_checkov,
    run_semgrep,
    run_git_diff,
    read_codeql_sarif,
    run_ast_rules,
    run_trivy_fs,
    run_trivy_image,
)
```

Replace with:

```python
from audit_packs_action.engines import (
    run_checkov,
    run_semgrep,
    run_git_diff,
    read_codeql_sarif,
    run_ast_rules,
    run_trivy_fs,
    run_trivy_image,
    run_tfsec,
    run_gitleaks,
)
```

- [ ] **Step 2: Add tfsec_enabled and gitleaks_enabled to analyze() signature**

Find the `analyze()` signature (already has `trivy_enabled`, `trivy_image` from Task 3):

```python
    trivy_enabled=False,
    trivy_image="",
):
```

Replace with:

```python
    trivy_enabled=False,
    trivy_image="",
    tfsec_enabled=False,
    gitleaks_enabled=False,
):
```

- [ ] **Step 3: Add tfsec + gitleaks tasks to _run_scans_parallel() inside analyze()**

Find inside `_run_scans_parallel()`:

```python
        trivy_img_task = (
            asyncio.create_task(
                TrivyEngine().run_scan_async("", {"image": trivy_image})
            )
            if (trivy_enabled and trivy_image)
            else None
        )
```

Add immediately after (still inside the function, before the `tasks = [...]` line):

```python
        from audit_packs_action.engines import TfsecEngine, GitleaksEngine

        tfsec_task = (
            asyncio.create_task(TfsecEngine().run_scan_async(repo_dir, {}))
            if tfsec_enabled
            else None
        )
        gitleaks_task = (
            asyncio.create_task(GitleaksEngine().run_scan_async(repo_dir, {}))
            if gitleaks_enabled
            else None
        )
```

Find the tasks list assembly:

```python
        tasks = [checkov_task, semgrep_task, ast_task]
        if codeql_task:
            tasks.append(codeql_task)
        if trivy_fs_task:
            tasks.append(trivy_fs_task)
        if trivy_img_task:
            tasks.append(trivy_img_task)
        results = await asyncio.gather(*tasks)

        c_sarif = results[0]
        s_sarif = results[1]
        a_sarif = results[2]
        idx = 3
        q_sarif = results[idx] if codeql_task else {"runs": []}
        if codeql_task:
            idx += 1
        t_fs_sarif = results[idx] if trivy_fs_task else {"runs": []}
        if trivy_fs_task:
            idx += 1
        t_img_sarif = results[idx] if trivy_img_task else {"runs": []}

        return c_sarif, s_sarif, q_sarif, a_sarif, t_fs_sarif, t_img_sarif
```

Replace with:

```python
        tasks = [checkov_task, semgrep_task, ast_task]
        if codeql_task:
            tasks.append(codeql_task)
        if trivy_fs_task:
            tasks.append(trivy_fs_task)
        if trivy_img_task:
            tasks.append(trivy_img_task)
        if tfsec_task:
            tasks.append(tfsec_task)
        if gitleaks_task:
            tasks.append(gitleaks_task)
        results = await asyncio.gather(*tasks)

        c_sarif = results[0]
        s_sarif = results[1]
        a_sarif = results[2]
        idx = 3
        q_sarif = results[idx] if codeql_task else {"runs": []}
        if codeql_task:
            idx += 1
        t_fs_sarif = results[idx] if trivy_fs_task else {"runs": []}
        if trivy_fs_task:
            idx += 1
        t_img_sarif = results[idx] if trivy_img_task else {"runs": []}
        if trivy_img_task:
            idx += 1
        tf_sarif = results[idx] if tfsec_task else {"runs": []}
        if tfsec_task:
            idx += 1
        gl_sarif = results[idx] if gitleaks_task else {"runs": []}

        return c_sarif, s_sarif, q_sarif, a_sarif, t_fs_sarif, t_img_sarif, tf_sarif, gl_sarif
```

- [ ] **Step 4: Update the asyncio.run() call and sync fallback in analyze()**

Find:

```python
    try:
        import asyncio

        (
            checkov_sarif,
            semgrep_sarif,
            codeql_sarif,
            ast_sarif,
            trivy_fs_sarif,
            trivy_img_sarif,
        ) = asyncio.run(_run_scans_parallel())
    except RuntimeError:
        checkov_sarif = run_checkov(repo_dir)
        semgrep_sarif = run_semgrep(repo_dir, rules_path)
        codeql_sarif = (
            read_codeql_sarif(codeql_sarif_dir) if codeql_sarif_dir else {"runs": []}
        )
        ast_sarif = run_ast_rules(repo_dir, ast_rules_dir)
        trivy_fs_sarif = run_trivy_fs(repo_dir) if trivy_enabled else {"runs": []}
        trivy_img_sarif = (
            run_trivy_image(trivy_image)
            if (trivy_enabled and trivy_image)
            else {"runs": []}
        )
```

Replace with:

```python
    try:
        import asyncio

        (
            checkov_sarif,
            semgrep_sarif,
            codeql_sarif,
            ast_sarif,
            trivy_fs_sarif,
            trivy_img_sarif,
            tfsec_sarif,
            gitleaks_sarif,
        ) = asyncio.run(_run_scans_parallel())
    except RuntimeError:
        checkov_sarif = run_checkov(repo_dir)
        semgrep_sarif = run_semgrep(repo_dir, rules_path)
        codeql_sarif = (
            read_codeql_sarif(codeql_sarif_dir) if codeql_sarif_dir else {"runs": []}
        )
        ast_sarif = run_ast_rules(repo_dir, ast_rules_dir)
        trivy_fs_sarif = run_trivy_fs(repo_dir) if trivy_enabled else {"runs": []}
        trivy_img_sarif = (
            run_trivy_image(trivy_image)
            if (trivy_enabled and trivy_image)
            else {"runs": []}
        )
        tfsec_sarif = run_tfsec(repo_dir) if tfsec_enabled else {"runs": []}
        gitleaks_sarif = run_gitleaks(repo_dir) if gitleaks_enabled else {"runs": []}
```

- [ ] **Step 5: Add tfsec and gitleaks findings to analyze() pipeline**

Find the Trivy findings block added in Task 3:

```python
    trivy_runs = trivy_fs_sarif.get("runs", []) + trivy_img_sarif.get("runs", [])
    if trivy_runs:
        merged_trivy = {"runs": trivy_runs}
        rule_confidences.update(extract_rule_confidences(merged_trivy, "trivy"))
        findings += sarif_to_findings(merged_trivy, "trivy")
```

Add immediately after:

```python
    if tfsec_sarif.get("runs"):
        rule_confidences.update(extract_rule_confidences(tfsec_sarif, "tfsec"))
        findings += sarif_to_findings(tfsec_sarif, "tfsec")
    if gitleaks_sarif.get("runs"):
        rule_confidences.update(extract_rule_confidences(gitleaks_sarif, "gitleaks"))
        findings += sarif_to_findings(gitleaks_sarif, "gitleaks")
```

- [ ] **Step 6: Add tfsec_enabled and gitleaks_enabled to assess() signature**

Find the `assess()` signature (already has `trivy_enabled`, `trivy_image` from Task 3):

```python
    trivy_enabled=False,
    trivy_image="",
):
```

Replace with:

```python
    trivy_enabled=False,
    trivy_image="",
    tfsec_enabled=False,
    gitleaks_enabled=False,
):
```

- [ ] **Step 7: Update _run_scans_parallel_assess() inside assess()**

Find inside `_run_scans_parallel_assess()`, after the trivy tasks:

```python
        return c_sarif, s_sarif, a_sarif, t_fs, t_img
```

Replace the full function:

```python
    async def _run_scans_parallel_assess():
        import asyncio
        from audit_packs_action.engines import (
            CheckovEngine,
            SemgrepEngine,
            ASTEngine,
            TrivyEngine,
            TfsecEngine,
            GitleaksEngine,
        )

        checkov_task = asyncio.create_task(CheckovEngine().run_scan_async(repo_dir, {}))
        semgrep_task = asyncio.create_task(
            SemgrepEngine().run_scan_async(repo_dir, {"rules_path": rules_path})
        )
        ast_task = asyncio.create_task(
            ASTEngine().run_scan_async(repo_dir, {"rules_dir": ast_rules_dir})
        )
        trivy_fs_task = (
            asyncio.create_task(TrivyEngine().run_scan_async(repo_dir, {}))
            if trivy_enabled
            else None
        )
        trivy_img_task = (
            asyncio.create_task(
                TrivyEngine().run_scan_async("", {"image": trivy_image})
            )
            if (trivy_enabled and trivy_image)
            else None
        )
        tfsec_task = (
            asyncio.create_task(TfsecEngine().run_scan_async(repo_dir, {}))
            if tfsec_enabled
            else None
        )
        gitleaks_task = (
            asyncio.create_task(GitleaksEngine().run_scan_async(repo_dir, {}))
            if gitleaks_enabled
            else None
        )

        tasks = [checkov_task, semgrep_task, ast_task]
        if trivy_fs_task:
            tasks.append(trivy_fs_task)
        if trivy_img_task:
            tasks.append(trivy_img_task)
        if tfsec_task:
            tasks.append(tfsec_task)
        if gitleaks_task:
            tasks.append(gitleaks_task)
        results = await asyncio.gather(*tasks)

        c_sarif, s_sarif, a_sarif = results[0], results[1], results[2]
        idx = 3
        t_fs = results[idx] if trivy_fs_task else {"runs": []}
        if trivy_fs_task:
            idx += 1
        t_img = results[idx] if trivy_img_task else {"runs": []}
        if trivy_img_task:
            idx += 1
        tf = results[idx] if tfsec_task else {"runs": []}
        if tfsec_task:
            idx += 1
        gl = results[idx] if gitleaks_task else {"runs": []}

        return c_sarif, s_sarif, a_sarif, t_fs, t_img, tf, gl
```

- [ ] **Step 8: Update asyncio.run() call and sync fallback in assess()**

Find:

```python
    try:
        import asyncio

        (
            checkov_sarif,
            semgrep_sarif,
            ast_sarif,
            trivy_fs_sarif,
            trivy_img_sarif,
        ) = asyncio.run(_run_scans_parallel_assess())
    except RuntimeError:
        checkov_sarif = run_checkov(repo_dir)
        semgrep_sarif = run_semgrep(repo_dir, rules_path)
        ast_sarif = run_ast_rules(repo_dir, ast_rules_dir)
        trivy_fs_sarif = run_trivy_fs(repo_dir) if trivy_enabled else {"runs": []}
        trivy_img_sarif = (
            run_trivy_image(trivy_image)
            if (trivy_enabled and trivy_image)
            else {"runs": []}
        )
```

Replace with:

```python
    try:
        import asyncio

        (
            checkov_sarif,
            semgrep_sarif,
            ast_sarif,
            trivy_fs_sarif,
            trivy_img_sarif,
            tfsec_sarif,
            gitleaks_sarif,
        ) = asyncio.run(_run_scans_parallel_assess())
    except RuntimeError:
        checkov_sarif = run_checkov(repo_dir)
        semgrep_sarif = run_semgrep(repo_dir, rules_path)
        ast_sarif = run_ast_rules(repo_dir, ast_rules_dir)
        trivy_fs_sarif = run_trivy_fs(repo_dir) if trivy_enabled else {"runs": []}
        trivy_img_sarif = (
            run_trivy_image(trivy_image)
            if (trivy_enabled and trivy_image)
            else {"runs": []}
        )
        tfsec_sarif = run_tfsec(repo_dir) if tfsec_enabled else {"runs": []}
        gitleaks_sarif = run_gitleaks(repo_dir) if gitleaks_enabled else {"runs": []}
```

- [ ] **Step 9: Add tfsec and gitleaks findings to assess() pipeline**

Find the Trivy findings block in `assess()` (added in Task 3):

```python
    trivy_runs = trivy_fs_sarif.get("runs", []) + trivy_img_sarif.get("runs", [])
    if trivy_runs:
        merged_trivy = {"runs": trivy_runs}
        rule_confidences.update(extract_rule_confidences(merged_trivy, "trivy"))
        findings += sarif_to_findings(merged_trivy, "trivy")
```

Add immediately after:

```python
    if tfsec_sarif.get("runs"):
        rule_confidences.update(extract_rule_confidences(tfsec_sarif, "tfsec"))
        findings += sarif_to_findings(tfsec_sarif, "tfsec")
    if gitleaks_sarif.get("runs"):
        rule_confidences.update(extract_rule_confidences(gitleaks_sarif, "gitleaks"))
        findings += sarif_to_findings(gitleaks_sarif, "gitleaks")
```

- [ ] **Step 10: Add env var reads and pass to analyze()/assess() in main()**

Find in `main()` (after the trivy env vars added in Task 3):

```python
    trivy_enabled = os.environ.get("TRIVY_ENABLED", "false").lower() == "true"
    trivy_image = os.environ.get("TRIVY_IMAGE", "")
```

Add immediately after:

```python
    tfsec_enabled = os.environ.get("TFSEC_ENABLED", "false").lower() == "true"
    gitleaks_enabled = os.environ.get("GITLEAKS_ENABLED", "false").lower() == "true"
```

Add to the `analyze(...)` call:

```python
            tfsec_enabled=tfsec_enabled,
            gitleaks_enabled=gitleaks_enabled,
```

Add to the `assess(...)` call:

```python
            tfsec_enabled=tfsec_enabled,
            gitleaks_enabled=gitleaks_enabled,
```

- [ ] **Step 11: Add tfsec and gitleaks inputs to action.yml**

After the `trivy-image:` input block, add:

```yaml
  tfsec-enabled:
    description: "Run tfsec Terraform scanner (disabled by default; overlaps with Checkov + Trivy)"
    default: "false"

  gitleaks-enabled:
    description: "Run gitleaks secrets scanner"
    default: "true"
```

In the `env:` section, after `TRIVY_IMAGE:`, add:

```yaml
    TFSEC_ENABLED:    ${{ inputs.tfsec-enabled }}
    GITLEAKS_ENABLED: ${{ inputs.gitleaks-enabled }}
```

- [ ] **Step 12: Add tfsec and gitleaks to Dockerfile**

After the trivy install block added in Task 3, add:

```dockerfile
# tfsec v1.28.11 — bump version here to upgrade (tfsec is deprecated; prefer trivy fs --scanners terraform)
RUN curl -sLo /usr/local/bin/tfsec \
    https://github.com/aquasecurity/tfsec/releases/download/v1.28.11/tfsec-linux-amd64 \
    && chmod +x /usr/local/bin/tfsec
# gitleaks v8.18.4 — bump version here to upgrade
RUN curl -sLo /tmp/gitleaks.tar.gz \
    https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz
```

- [ ] **Step 13: Update README Supported Scanners table**

Find the scanners table in `README.md`:

```markdown
| Trivy   | Planned |
| tfsec   | Planned |
| gitleaks | Planned |
```

Replace with:

```markdown
| Trivy   | Supported |
| tfsec   | Supported |
| gitleaks | Supported |
```

- [ ] **Step 14: Run full suite**

```bash
uv run pytest tests/ -v --ignore=tests/test_live_llm.py --ignore=tests/test_real_world_repos.py -q 2>&1 | tail -10
```

Expected: 0 failures.

- [ ] **Step 15: Commit (PR 2 ready)**

```bash
git add packages/action/src/audit_packs_action/cli.py packages/action/src/audit_packs_action/engines.py action.yml Dockerfile README.md
git commit -m "feat: wire tfsec and gitleaks into pipeline, action.yml, Dockerfile (PR 2)"
```
