# Scanner Coverage Expansion — Design Spec

**Date:** 2026-06-27
**Scope:** Add Trivy (filesystem + image), tfsec, and gitleaks scanners to the audit-packs pipeline via Approach B: SARIF engine adapters + curated pack mappings.

---

## Background

audit-packs v0.3.0 supports Checkov, Semgrep, CodeQL, and AST rules. The README lists Trivy, tfsec, and gitleaks as "Planned." Each covers a distinct threat surface not fully addressed by the existing engines:

| Scanner | Surface | Key gap filled |
|---------|---------|----------------|
| Trivy | Container images, Dockerfiles, OS/app CVEs, IaC misconfigs | Container posture + CVE-to-control linking |
| tfsec | Terraform-specific IaC misconfigs | tfsec rules diverge from Checkov; many pipelines run both |
| gitleaks | Hardcoded secrets in code | IA-5 / credential management — not covered by IaC scanners |

**Delivery split:** Trivy ships first (separate PR). tfsec + gitleaks ship together in a second PR. This spec covers all three in one document since architecture is identical.

---

## Architecture

No pipeline restructuring. Each new scanner slots in as a `BaseEngine` subclass — the same contract as CheckovEngine, SemgrepEngine, etc. SARIF output flows through the existing `normalize → evidence → adjudicate → map_findings` chain unchanged.

```
[TrivyEngine fs]   [TrivyEngine image]   [TfsecEngine]   [GitleaksEngine]
       │                    │                   │                │
       └────────────────────┴───────────────────┴────────────────┘
                                    │
                           sarif_to_findings(sarif, engine="trivy"|"tfsec"|"gitleaks")
                                    │
                            (existing pipeline)
                                    │
                           map_findings → pack YAML lookup
                                    │
                           ControlFinding with control attribution
```

**IO boundary:** `engines.py` is already an approved IO module. No new IO boundary exceptions required.

**CVE findings:** Trivy emits findings with `check_id = "CVE-YYYY-NNNNN"` for OS/app vulnerabilities. These pass through `sarif_to_findings` normally but will not match any pack mapping entry (pack YAML maps structural `AVD-*` rules only). CVE findings appear in raw SARIF output but are not crosswalked to compliance controls in Phase 1. Wildcard `CVE-* → SI-2` is deferred to Phase 2 and requires extending `_canonical_index` to support prefix matching.

---

## Section 1: Engine Additions (`engines.py`)

### `TrivyEngine`

Handles both filesystem and image scanning via the `options` dict — the same pattern as `SemgrepEngine` (uses `options["rules_path"]`) and `ASTEngine` (uses `options["rules_dir"]`).

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
                cmd = [_resolve_executable("trivy"), "image",
                       "--format", "sarif", "--output", out_file, image]
            else:
                cmd = [_resolve_executable("trivy"), "fs",
                       "--format", "sarif", "--output", out_file, target]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=_DEFAULT_TIMEOUT)
            except asyncio.TimeoutError as exc:
                proc.kill()
                raise RuntimeError(f"trivy timed out after {_DEFAULT_TIMEOUT}s") from exc
            # exit 0 = clean, exit 1 = findings found — both are success
            if proc.returncode is not None and proc.returncode >= 2:
                raise RuntimeError(
                    f"trivy exited with code {proc.returncode}: {stderr.decode(errors='replace').strip()}"
                )
            if os.path.exists(out_file):
                with open(out_file) as fh:
                    return json.load(fh)
            return {"runs": []}
```

Convenience functions:
```python
def run_trivy_fs(target_dir: str) -> dict:
    return TrivyEngine().run_scan(target_dir, {})

def run_trivy_image(image: str) -> dict:
    return TrivyEngine().run_scan("", {"image": image})
```

### `TfsecEngine`

```python
class TfsecEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "tfsec"

    async def run_scan_async(self, target: str, options: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "tfsec.sarif")
            cmd = [_resolve_executable("tfsec"), "--format", "sarif",
                   "--out", out_file, target]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=_DEFAULT_TIMEOUT)
            except asyncio.TimeoutError as exc:
                proc.kill()
                raise RuntimeError(f"tfsec timed out after {_DEFAULT_TIMEOUT}s") from exc
            if proc.returncode is not None and proc.returncode >= 2:
                raise RuntimeError(
                    f"tfsec exited with code {proc.returncode}: {stderr.decode(errors='replace').strip()}"
                )
            if os.path.exists(out_file):
                with open(out_file) as fh:
                    return json.load(fh)
            return {"runs": []}

def run_tfsec(target_dir: str) -> dict:
    return TfsecEngine().run_scan(target_dir, {})
```

**Note on tfsec deprecation:** Aqua merged tfsec into Trivy (`trivy fs --scanners terraform`). tfsec still ships as a standalone binary and is widely installed in existing pipelines. We support it with `tfsec_enabled=False` as default — users opt in if they have it installed.

### `GitleaksEngine`

```python
class GitleaksEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "gitleaks"

    async def run_scan_async(self, target: str, options: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "gitleaks.sarif")
            cmd = [_resolve_executable("gitleaks"), "detect",
                   "--report-format", "sarif",
                   "--report-path", out_file,
                   "--source", target,
                   "--no-git"]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=_DEFAULT_TIMEOUT)
            except asyncio.TimeoutError as exc:
                proc.kill()
                raise RuntimeError(f"gitleaks timed out after {_DEFAULT_TIMEOUT}s") from exc
            # exit 0 = clean, exit 1 = leaks found, ≥ 126 = error
            if proc.returncode is not None and proc.returncode not in (0, 1):
                raise RuntimeError(
                    f"gitleaks exited with code {proc.returncode}: {stderr.decode(errors='replace').strip()}"
                )
            if os.path.exists(out_file):
                with open(out_file) as fh:
                    return json.load(fh)
            return {"runs": []}

def run_gitleaks(target_dir: str) -> dict:
    return GitleaksEngine().run_scan(target_dir, {})
```

---

## Section 2: CLI Wiring (`cli.py`)

### New parameters

`assess()` and `analyze()` gain four new parameters:

```python
trivy_enabled: bool = True,
trivy_image: str = "",          # empty = no image scan; "myapp:latest" = scan that image
tfsec_enabled: bool = False,    # off by default; tfsec overlaps with Checkov + Trivy
gitleaks_enabled: bool = True,
```

Read from env vars: `TRIVY_ENABLED`, `TRIVY_IMAGE`, `TFSEC_ENABLED`, `GITLEAKS_ENABLED`.

### `_run_scans_parallel()` additions

Inside the existing async function, after the existing four tasks:

```python
if trivy_enabled:
    trivy_fs_task = asyncio.create_task(TrivyEngine().run_scan_async(repo_dir, {}))
    tasks.append(trivy_fs_task)
if trivy_enabled and trivy_image:
    trivy_img_task = asyncio.create_task(TrivyEngine().run_scan_async("", {"image": trivy_image}))
    tasks.append(trivy_img_task)
if tfsec_enabled:
    tfsec_task = asyncio.create_task(TfsecEngine().run_scan_async(repo_dir, {}))
    tasks.append(tfsec_task)
if gitleaks_enabled:
    gitleaks_task = asyncio.create_task(GitleaksEngine().run_scan_async(repo_dir, {}))
    tasks.append(gitleaks_task)
```

Results normalized with their engine name:
```python
trivy_findings = sarif_to_findings(trivy_sarif, "trivy")   # fs + image merged
tfsec_findings = sarif_to_findings(tfsec_sarif, "tfsec")
gitleaks_findings = sarif_to_findings(gitleaks_sarif, "gitleaks")
```

### `_normalize_rule_id` check

`normalize.py`'s `_normalize_rule_id` strips path separators from Semgrep IDs (e.g., `rules/foo.bar` → `foo.bar`). Trivy AVD IDs (`AVD-AWS-0132`), tfsec IDs (`aws-s3-enable-bucket-encryption`), and gitleaks IDs (`aws-access-token`) don't contain `.` and pass through unchanged. No changes needed in `normalize.py`.

---

## Section 3: Pack YAML Mapping Additions (`packs/nist-800-53/controls.yaml`)

Additions only — no controls removed or renamed. Crosswalk packs (SOC2, HIPAA, ISO27001, PCI-DSS, FedRAMP, GDPR, Org Policy) inherit these mappings transitively via `_canonical_index` with no changes required.

**Verification requirement:** AVD rule IDs must be verified against `trivy checks --format json` output before implementation, and tfsec IDs against `tfsec --print-checks`. Both scanners update their rule ID sets across minor versions. The IDs below are the intended mappings; final list may differ slightly.

### Trivy mappings (AVD-* structural rules only)

Added to `supported_scanners` and `mappings` lists on existing controls:

| Control | check_ids to add (engine: trivy) |
|---------|----------------------------------|
| SC-28 (Protection of Information at Rest) | AVD-AWS-0132, AVD-AWS-0088, AVD-AWS-0178, AVD-AWS-0083, AVD-AWS-0065 |
| SC-8 (Transmission Confidentiality) | AVD-AWS-0020, AVD-AWS-0123 |
| SC-13 (Cryptographic Protection) | AVD-AWS-0020, AVD-AWS-0123 |
| SC-7 (Boundary Protection) | AVD-AWS-0107, AVD-AWS-0026, AVD-AWS-0175 |
| IA-5 (Authenticator Management) | AVD-AWS-0025, AVD-AWS-0057 |
| SC-12 (Cryptographic Key Management) | AVD-AWS-0065 |
| AU-2 (Audit Events) | AVD-AWS-0001, AVD-AWS-0002 |
| CM-7 (Least Functionality) | AVD-AWS-0102 |

**CVEs (SI-2):** Not mapped in Phase 1. Document as known limitation in README. Phase 2 will add prefix-match support to `_canonical_index` so any `CVE-*` finding maps to SI-2 automatically.

### tfsec mappings

| Control | check_ids to add (engine: tfsec) |
|---------|----------------------------------|
| SC-28 | aws-s3-enable-bucket-encryption, aws-rds-encrypt-cluster-storage-data, aws-ebs-enable-volume-encryption |
| SC-7 | aws-ec2-no-public-ip-subnet, aws-s3-no-public-buckets, aws-s3-no-public-access-with-acl |
| IA-5 | general-secrets-no-plaintext-exposure, aws-ecs-no-plaintext-exposed-creds |
| AC-6 (Least Privilege) | aws-iam-no-root-usage, aws-iam-no-user-attached-policies |
| IA-2 (Identification and Authentication) | aws-iam-enforce-mfa |
| AU-2 | aws-cloudtrail-enable-all-regions, aws-eks-enable-control-plane-logging |
| AU-3 (Content of Audit Records) | aws-lambda-enable-tracing |
| SC-12 | aws-kms-auto-rotate-keys |

### gitleaks mappings

All gitleaks rules indicate hardcoded credentials — all map to IA-5. Private key findings additionally map to SC-13.

| Control | check_ids to add (engine: gitleaks) |
|---------|-------------------------------------|
| IA-5 (Authenticator Management) | aws-access-token, github-pat, github-oauth, github-app-token, github-fine-grained-pat, slack-bot-token, slack-user-token, slack-webhook-url, stripe-access-token, stripe-restricted-key, google-api-key, google-oauth, heroku-api-key, twilio-api-key, generic-api-key, private-key |
| SC-13 (Cryptographic Protection) | private-key |

---

## Section 4: Infrastructure

### `action.yml`

Four new inputs:

```yaml
trivy-enabled:
  description: 'Run Trivy filesystem scan for IaC misconfigs and CVEs'
  default: 'true'

trivy-image:
  description: 'Docker image tag to scan with Trivy (e.g. myapp:latest). Empty = skip image scan.'
  default: ''

tfsec-enabled:
  description: 'Run tfsec Terraform scanner (disabled by default; overlaps with Checkov + Trivy)'
  default: 'false'

gitleaks-enabled:
  description: 'Run gitleaks secrets scanner'
  default: 'true'
```

Passed to the container as env vars: `TRIVY_ENABLED`, `TRIVY_IMAGE`, `TFSEC_ENABLED`, `GITLEAKS_ENABLED`.

### `Dockerfile`

Install block added after existing scanner installs. Each scanner pinned to a specific version with a comment marking it for Dependabot / manual update:

```dockerfile
# trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin v0.51.1

# tfsec (legacy; prefer trivy fs --scanners terraform for new repos)
RUN curl -sLo /usr/local/bin/tfsec \
    https://github.com/aquasecurity/tfsec/releases/download/v1.28.11/tfsec-linux-amd64 \
    && chmod +x /usr/local/bin/tfsec

# gitleaks
RUN curl -sLo /tmp/gitleaks.tar.gz \
    https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz
```

For Docker image scanning (`trivy image`), the Dockerfile does not need Docker-in-Docker. The GitHub Action step must mount the Docker socket or build + push the image before invoking audit-packs. This is documented in the README action example — no code change required.

---

## Section 5: Tests

### New test files

**`tests/test_trivy_engine.py`**
- `test_trivy_fs_returns_findings` — mock subprocess returning a minimal SARIF dict; verify `sarif_to_findings(result, "trivy")` returns `Finding` objects with `engine="trivy"`
- `test_trivy_image_mode` — verify `options={"image": "myapp:latest"}` builds command with `image` subcommand
- `test_trivy_exit_code_1_not_error` — exit code 1 (findings found) must not raise
- `test_trivy_exit_code_2_raises` — exit code 2 must raise `RuntimeError`
- `test_trivy_missing_binary_raises` — `_resolve_executable` fallback with non-existent binary raises on subprocess spawn

**`tests/test_tfsec_engine.py`**
- `test_tfsec_returns_findings` — same mock pattern
- `test_tfsec_exit_code_1_not_error`
- `test_tfsec_exit_code_2_raises`

**`tests/test_gitleaks_engine.py`**
- `test_gitleaks_returns_findings`
- `test_gitleaks_exit_code_1_not_error` — code 1 = secrets found, not an engine error
- `test_gitleaks_exit_code_126_raises` — codes ≥ 126 are errors

### Additions to `tests/test_packs.py`

Three inline-pack tests using v2 format (same pattern as existing inline tests):

- `test_trivy_avd_maps_to_sc28` — inline pack with `engine: trivy, check_id: AVD-AWS-0132` → verifies `map_findings` returns `ControlFinding` with `control_id="SC-28"`
- `test_gitleaks_secret_maps_to_ia5` — `engine: gitleaks, check_id: aws-access-token` → `IA-5`
- `test_tfsec_iam_maps_to_ac6` — `engine: tfsec, check_id: aws-iam-no-root-usage` → `AC-6`

---

## Files Created / Modified

| Action | Path |
|--------|------|
| **Modify** | `packages/action/src/audit_packs_action/engines.py` — add `TrivyEngine`, `TfsecEngine`, `GitleaksEngine` + convenience functions |
| **Modify** | `packages/action/src/audit_packs_action/cli.py` — new params, new tasks in `_run_scans_parallel()`, new env var reads |
| **Modify** | `packs/nist-800-53/controls.yaml` — add trivy/tfsec/gitleaks mappings to 10 controls |
| **Modify** | `action.yml` — four new inputs |
| **Modify** | `Dockerfile` — install trivy, tfsec, gitleaks |
| **Create** | `tests/test_trivy_engine.py` |
| **Create** | `tests/test_tfsec_engine.py` |
| **Create** | `tests/test_gitleaks_engine.py` |
| **Modify** | `tests/test_packs.py` — three new inline-pack tests |

README `Supported Scanners` table: Trivy, tfsec, gitleaks move from "Planned" to "Supported".

---

## Known Limitations (Phase 2)

1. **CVE findings not crosswalked.** Trivy emits `CVE-YYYY-NNNNN` findings for OS/app vulnerabilities. These appear in raw SARIF output (`build_sarif`) but are not attributed to compliance controls. Phase 2: extend `_canonical_index` with prefix-match support so `check_id: "CVE-*"` maps to SI-2 (Flaw Remediation).

2. **Docker image scan requires pre-built image.** The action cannot build the image itself. Phase 2: auto-detect `Dockerfile` and run `docker build` before `trivy image` when `trivy-image` is not specified but a `Dockerfile` is present.

3. **tfsec overlap with Checkov/Trivy.** Both tfsec and Checkov cover Terraform misconfigs. Duplicate findings from both engines map to the same controls but appear as separate `ControlFinding` entries. Phase 2: deduplication layer in `map_findings` to collapse same-file/same-line/same-control duplicates across engines.
