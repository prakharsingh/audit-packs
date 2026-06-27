# CHANGELOG


## v0.5.0 (2026-06-27)

### Bug Fixes

- **evidence**: Trigger release for Nist80053Agent parsing fixes
  ([#14](https://github.com/prakharsingh/audit-packs/pull/14),
  [`91ab7db`](https://github.com/prakharsingh/audit-packs/commit/91ab7dbc1171aa904d6487db9ed7089d0a62efe9))

trigger release for Nist80053Agent parsing fixes

### Features

- **ecosystem**: Pluggable scanner plugins, pack registry CLI & contribution tooling
  ([#15](https://github.com/prakharsingh/audit-packs/pull/15),
  [`990cf7f`](https://github.com/prakharsingh/audit-packs/commit/990cf7f2c365ed53f620ff71e78312900647322f))

* feat: refactor notifications, add onboarding features and vscode extension template

- Add Slack/Jira webhook integration for compliance alert notifications - Implement compact coverage
  summaries to prevent exceeding Slack payload sizes - Handle full scan failures correctly in Jira
  tickets - Add interactive bootstrapping wizard (--init) and policy validator (--validate-policy) -
  Introduce vscode-extension template - Add test coverage for notifications and CLI wizard features

* ci: add workflow to publish vscode extension to marketplace and openvsx

- Add GitHub Actions workflow publish-extension.yml to automatically compile and publish the
  extension when a new release is cut - Configure tsconfig.json and build scripts in
  packages/vscode-extension/package.json to compile the extension - Update .gitignore to ignore the
  compiled out/ directory - Update docs/SETUP.md with instructions on setting up publishing secret
  tokens

* ci: fix vscode extension packaging metadata, ignore files, and license

- Add repository field to package.json manifest - Add .vscodeignore to exclude development and
  configuration files from the packaged bundle - Copy main LICENSE into extension folder for
  inclusion in VS Marketplace

* ci: add PyPI automatic publishing workflow

* docs: update installation & release docs and rename package to audit-packs

* test: allow expected quality gate failure in docker smoke test

* ci(vscode-extension): publish to Open VSX Registry and support local VS VSIX install

* build: configure uv link-mode to copy for cross-filesystem compatibility

* feat(ecosystem): pluggable scanner plugins, pack registry CLI, and docs

- Add DeclarativeEngine and load_plugins() to engines.py for YAML-based and entrypoint-based
  third-party scanner plugin support - Add --scanners-dir CLI arg to analyze() and assess() enabling
  concurrent execution of custom plugins alongside built-in engines - Add pack subcommand namespace:
  pack init, validate, test, publish, install - pack install resolves GitHub owner/repo@tag
  shorthands, HTTPS URLs, and local tarballs; extracts and caches to ~/.audit-packs/installed/ -
  pack publish packages controls.yaml, metadata.json, rules/, agents/ into a versioned .tar.gz for
  redistribution - Update _pack_path() to transparently resolve packs from both local dir and global
  ~/.audit-packs/installed/ registry cache - Add unit tests covering declarative engine loading,
  pack init/validate, and publish/install roundtrip (238 passed) - Update docs/SETUP.md with scanner
  plugin and pack CLI usage - Update docs/ONBOARDING.md to use pack CLI for crosswalk pack authoring
  - fix(ci): use GH_TOKEN env var instead of github_token input for python-semantic-release v9 to
  resolve GITHUB_-prefixed secret error

* fix(ci): use github.token instead of secrets.GITHUB_TOKEN

GitHub's validator rejects any secrets context reference whose name starts with GITHUB_.
  github.token is the identical built-in token but accessed through the github expression context,
  bypassing the restriction entirely.

* fix(engines): gracefully skip missing scanner executables

Instead of crashing with a RuntimeError when checkov or semgrep are not on PATH (FileNotFoundError
  from subprocess), print a clear warning to stderr and return an empty SARIF so other engines can
  still run.

* fix(init): use github.token instead of secrets.GITHUB_TOKEN in generated audit.yml

The --init wizard was embedding GITHUB_TOKEN as an env var name in the generated
  .github/workflows/audit.yml template. GitHub's validator rejects any env/secret name starting with
  GITHUB_ in user-defined contexts.

Switched to GH_TOKEN: ${{ github.token }} which is the identical built-in token via the github
  expression context and has no naming restriction.

* fix(cli): bundle default semgrep rules and fix crash when rules_path is empty

### Refactoring

- **evidence**: Robust dependency parsing and line lookup in Nist80053Agent
  ([#13](https://github.com/prakharsingh/audit-packs/pull/13),
  [`d0ccfe0`](https://github.com/prakharsingh/audit-packs/commit/d0ccfe05a1e33ae003cf78e0e676c87b41659baa))

- Replaced simple substring checks in _find_toml_line with strict regex boundary checks
  (?<![a-zA-Z0-9_.-]){term}(?![a-zA-Z0-9_.-]) to prevent package name collisions (e.g. matching
  'flask-app' when looking for 'flask'). - Stripped packaging extras (e.g. 'flask[async]') before
  running validation regex or looking up line numbers. - Added unpinned optional-dependencies check
  in PEP 621 pyproject.toml. - Supported modern Poetry group dependencies (e.g. group.dev) and
  legacy dev-dependencies. - Added comprehensive unit tests in tests/test_agents.py.


## v0.4.0 (2026-06-27)

### Features

- Scanner coverage expansion — Trivy, tfsec, gitleaks
  ([#12](https://github.com/prakharsingh/audit-packs/pull/12),
  [`8910307`](https://github.com/prakharsingh/audit-packs/commit/891030719f45ab65c9f22d4029be194758ee926b))

* docs: add scanner expansion design spec (Trivy + tfsec + gitleaks)

Three new SARIF engine adapters + curated pack mappings for nist-800-53. Trivy covers fs + image
  scanning; gitleaks covers IA-5; tfsec is opt-in (legacy overlap with Checkov/Trivy). CVE→SI-2
  wildcard deferred to Phase 2.


## v0.3.1 (2026-06-26)

### Bug Fixes

- **action**: Shorten description for marketplace compliance
  ([`92e3b79`](https://github.com/prakharsingh/audit-packs/commit/92e3b79e7d8f0ae2674f8cb56c1f5d4b7d494153))


## v0.3.0 (2026-06-26)

### Bug Fixes

- Miscellaneous fixes -
  ([`252ae8a`](https://github.com/prakharsingh/audit-packs/commit/252ae8aec26734eae4db19f97089035cfafd07d5))

- Update run_e2e_manual.py imports for new package names
  ([`95d1c71`](https://github.com/prakharsingh/audit-packs/commit/95d1c71b69b5ed03fd0d0d19e863a7325849bb37))

### Chores

- Add monorepo package scaffolding and workspace config
  ([`bd373b6`](https://github.com/prakharsingh/audit-packs/commit/bd373b68e58465d325635aa2c05ee8c9e6f67ab0))

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- Untrack local agent/IDE files and update gitignore for open sourcing
  ([`a21df68`](https://github.com/prakharsingh/audit-packs/commit/a21df68ac7993568195dc36065e16c5ecbdd583d))

To prepare the repository for open-sourcing, we keep it minimal by untracking local agent and
  developer helper files (.agent, .agents, .claude, AGENTS.md, gemini.md, CLAUDE.md) that are
  specific to the agentic workspace, while updating .gitignore to exclude them.

### Continuous Integration

- Use uv in test workflow for monorepo support
  ([`206f29c`](https://github.com/prakharsingh/audit-packs/commit/206f29c4999a868e24ba10329f398cb6898e2dad))

### Documentation

- Add architectural alignment design spec
  ([`f4e74f4`](https://github.com/prakharsingh/audit-packs/commit/f4e74f4a519f1e14874e73248da817a1654d0c30))

Five-package monorepo split, pack schema v2, terminology rename, README repositioning.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- Add architectural alignment implementation plan
  ([`4b0cd3e`](https://github.com/prakharsingh/audit-packs/commit/4b0cd3ef73bee05cb38acdeee1f936c7d30cd872))

5-task plan: pack schema v2, terminology rename, monorepo scaffolding, module move, README update.
  Full code for every step.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- Fix three spec errors — dep graph, roles wrapper, gap count
  ([`f17e073`](https://github.com/prakharsingh/audit-packs/commit/f17e073c633da6b7e4f9ae64b042a3bcfc4dd35e))

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- Reposition as Evidence-first Compliance Intelligence Engine
  ([`d4b40d0`](https://github.com/prakharsingh/audit-packs/commit/d4b40d043e3436f70b8d25a5350f2f02db601a2d))

- Update ONBOARDING.md for monorepo package layout and schema v2
  ([`5886a5a`](https://github.com/prakharsingh/audit-packs/commit/5886a5a47f72e6ce2a943a37ff55e7d401c3f1ed))

### Features

- Big-bang module move — src/audit_packs/ → packages/*/src/
  ([`6bf70a6`](https://github.com/prakharsingh/audit-packs/commit/6bf70a690bbbfae6cc00d3dca6ad81b64b5090df))

Move all 14 source modules to their respective package homes: - models, diff, normalize, dataflow →
  packages/core/src/audit_packs_core/ - packs, coverage, oscal →
  packages/mapping/src/audit_packs_mapping/ - evidence, agents →
  packages/evidence/src/audit_packs_evidence/ - adjudicate, confidence →
  packages/ai/src/audit_packs_ai/ - engines, report, cli → packages/action/src/audit_packs_action/

Update all imports in moved files and 25 test files to use new package names. Remove "src" from
  pytest pythonpath. Fix packages/action/pyproject.toml (dependencies was nested under
  [project.urls]). Fix Dockerfile install order (packages/ai must precede packages/action to satisfy
  audit-packs-ai dep).

Tests: 186 passed, 9 skipped (env-based), 0 failed.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- Pack schema v2 — per-framework dirs, evidence_requirements, mappings
  ([`ad7a24f`](https://github.com/prakharsingh/audit-packs/commit/ad7a24fe0c89a3659bd7280255381abbcb3f1e14))

- Migrate 8 pack files from flat packs/<fw>.yaml (v1, checks/ids) to packs/<fw>/controls.yaml (v2,
  mappings/check_id) - Add scripts/migrate_packs_v2.py for the one-time migration - Add
  ControlFinding.evidence_requirements: tuple = () to models.py - Rewrite packs.py: _pack_path() ->
  <fw>/controls.yaml, _canonical_index and map_findings carry evidence_requirements through,
  load_pack reads org-policy from new subdir path - Update tests/test_packs.py: 4 inline-pack tests
  use v2 format + new test_map_findings_populates_evidence_requirements - Update
  tests/test_rules.py: _nist_semgrep_ids() reads v2 mappings

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

### Refactoring

- Rename adversarial→challenger, judge→consensus in AI ensemble
  ([`5afd754`](https://github.com/prakharsingh/audit-packs/commit/5afd7545dcb619b7c9673769352eec964abc4830))


## v0.2.0 (2026-06-25)

### Bug Fixes

- Resolve 6 review findings in ASTEngine, normalize, and cli
  ([`2fda38e`](https://github.com/prakharsingh/audit-packs/commit/2fda38e19192842b032055ed204a00f36ef2f6ed))

- normalize.py: extract _normalize_rule_id() helper and use it in both sarif_to_findings and
  extract_rule_confidences (with new engine param) so confidence dict keys always match
  Finding.check_id — fixes silent 0.6 fallback for all non-semgrep dotted ruleIds - engines.py: add
  sys.modules cache check in _run_ast_rules_sync to avoid re-exec'ing rule files on every call; move
  del sys.modules on exec_module failure so broken modules are not left cached - engines.py: replace
  asyncio.get_event_loop() with get_running_loop() in CodeQLEngine and ASTEngine (deprecated 3.10+,
  broken in 3.12) - engines.py: add "env" to os.walk exclusion list to prevent scanning python -m
  venv env virtualenvs - cli.py: resolve ast_rules_dir relative to repo_dir at the top of analyze()
  and assess() so direct callers get correct path regardless of process CWD; pass engine name to
  extract_rule_confidences() calls - CLAUDE.md: document ASTEngine as the sole sanctioned in-process
  engine exception to the "never re-implement detection logic" rule

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- Resolve 8 bugs in ASTEngine, async gather, test isolation, and path handling
  ([`fbed178`](https://github.com/prakharsingh/audit-packs/commit/fbed1782f368b0e438b805d481c29059da3af796))

- engines.py: namespace rule modules as audit_packs.ast_rules.<name> to prevent clobbering stdlib
  modules (ast, os, re, etc.) if a rule file shares a name - engines.py: run
  ASTEngine._run_ast_rules_sync via run_in_executor so it no longer blocks the event loop during
  filesystem walk and AST parsing - cli.py: include ast_task inside asyncio.gather in analyze() so
  exceptions are handled uniformly and don't trigger redundant re-runs of checkov/semgrep - cli.py:
  join relative ast_rules_dir to workspace in main() so it resolves correctly when CWD differs from
  GITHUB_WORKSPACE - test_ast_rules.py: guard _load_rule() against None spec/spec.loader so a
  missing rule file raises ImportError rather than crashing all test collection - test_live_llm.py:
  replace shutil.rmtree('.audit-cache') with isolated_cache fixture that patches
  adjudicate._CACHE_DIR to tmp_path per test - test_live_llm.py: wrap test bodies in try/finally to
  reset server_fail_verifier, eliminating ordering-sensitive global state - test_live_llm.py: bind
  MockLLMServer to port 0 and read assigned port from server_address[1], eliminating TOCTOU race in
  get_free_port() - test_live_llm.py: skip if openai package not installed -
  test_e2e_integration.py: skip if checkov or semgrep not on PATH

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

### Features

- Implement Option A AST rules engine and Option C live LLM test coverage
  ([`407009b`](https://github.com/prakharsingh/audit-packs/commit/407009bb5ccf589dbba7bbc70d7fe4c8e69a03ba))


## v0.1.1 (2026-06-25)

### Bug Fixes

- Add [ai] optional deps; actionable ImportError for missing LLM packages; Dockerfile INSTALL_AI ARG
  ([`bd95e7f`](https://github.com/prakharsingh/audit-packs/commit/bd95e7fe23afd161bea4ec3b3d8b674918cf0a6f))

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- Correct ScoredFinding field access in integration test
  ([`cd5b9ba`](https://github.com/prakharsingh/audit-packs/commit/cd5b9ba20cdd0ae612d28de575a088a01f9fb665))

- Key ev_conf_map by (check_id, file, line) tuple in analyze() to prevent id() aliasing
  ([`60e7445`](https://github.com/prakharsingh/audit-packs/commit/60e74450df8c89a094b741d44f58805bda53c1ba))

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- Key ev_conf_map by tuple in assess(); add codeql_sarif_dir param to assess()
  ([`e6f7dcf`](https://github.com/prakharsingh/audit-packs/commit/e6f7dcfbfed57347e524f4d9616d72d299765a3d))

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- Map ssl-verify-disabled, tls-enabled-false, pii-variable-name to NIST controls; add
  forward-direction pack test
  ([`1d84942`](https://github.com/prakharsingh/audit-packs/commit/1d84942258f8e5b2d382de1f13f01214e63b745f))


## v0.1.0 (2026-06-25)

### Chores

- Add .agents compatibility symlink and finalize episodic log
  ([`b633808`](https://github.com/prakharsingh/audit-packs/commit/b633808cab78615203c94c3d3fcab2f84c18078e))

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- Configure pre-commit hooks, semantic versioning, and CI/CD release workflow
  ([`70fe726`](https://github.com/prakharsingh/audit-packs/commit/70fe726298402eb5fa8e10af6aac4a88f0abf8a8))

- Sync agentic brain — skills, memory, and install manifest
  ([`bb3e00a`](https://github.com/prakharsingh/audit-packs/commit/bb3e00ade6266f787900cd2109d4eed094b705eb))

Update skill index and manifest with new engineering agent skills, refresh working memory and review
  queue, graduate two candidates, add episodic learnings, and update install.json.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- Update episodic agent learnings log
  ([`02633a3`](https://github.com/prakharsingh/audit-packs/commit/02633a30d942077bf380f4c8253d34920f840c23))

### Documentation

- Add codebase onboarding guide, compliance design plan, and repository documentation
  ([`60fa991`](https://github.com/prakharsingh/audit-packs/commit/60fa99114f7b2ef3bf2f1bdb1ecd61a6888d6b74))

- Compliance framework extension design spec
  ([`0c94c97`](https://github.com/prakharsingh/audit-packs/commit/0c94c973c5dd2d3b2124ff1fd8b63e659ba339e9))

Phase 1: evidence enrichment, prompt-agent ensemble, confidence-weighted false-positive gate. Phase
  2 stub: DetectionAgent ABC for framework-specific detection agents (GDPR, HIPAA, SOC2, FedRAMP,
  OrgPolicy).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

### Features

- Add default semgrep detection rules
  ([`3378226`](https://github.com/prakharsingh/audit-packs/commit/3378226004fd248acde71715d0a47e38eff65240))

- Add FedRAMP, GDPR, HIPAA, ISO 27001, PCI-DSS, and Org Policy compliance packs
  ([`5c7d692`](https://github.com/prakharsingh/audit-packs/commit/5c7d6925141146a2788557147aaacef3717feb47))

- Add SEO metadata to coverage HTML and extend report pipeline
  ([`2fa6341`](https://github.com/prakharsingh/audit-packs/commit/2fa6341040cd5197cd9ab14c41f29380796beb29))

Add seo-title, seo-description, seo-canonical-url action inputs; inject Open Graph, JSON-LD, and
  canonical link tags into coverage.html output. Extend CLI to thread SEO params through assess().
  Add CHANGELOG.md and document release workflow in CONTRIBUTING.md.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>

- Format review comments and implement PR gating based on severity threshold
  ([#7](https://github.com/prakharsingh/audit-packs/pull/7),
  [`0888b18`](https://github.com/prakharsingh/audit-packs/commit/0888b184d19f1af2356cf9cd506fe0328ee3fc7b))

- Implement 6-signal composite confidence scoring model
  ([`7866f67`](https://github.com/prakharsingh/audit-packs/commit/7866f67ba9e1b8cc97ceebbf7a814eb6f1510102))

- Implement checkov and semgrep subprocess runners with custom weak-cipher rule
  ([#6](https://github.com/prakharsingh/audit-packs/pull/6),
  [`b99c011`](https://github.com/prakharsingh/audit-packs/commit/b99c011c42389fea6d1471bc20d24a88034c1c93))

- Implement control coverage computation
  ([`b2bdb6f`](https://github.com/prakharsingh/audit-packs/commit/b2bdb6fc9508612d3b2ca67123265f707ce55ada))

- Implement control-mapping pack loader and crosswalk mapper
  ([#5](https://github.com/prakharsingh/audit-packs/pull/5),
  [`2b770bf`](https://github.com/prakharsingh/audit-packs/commit/2b770bfd635726d7ec38764536c36e79a53a9bfc))

- Implement data flow analysis source-transform-sink extraction
  ([`e9fe6a1`](https://github.com/prakharsingh/audit-packs/commit/e9fe6a17a779a984629e63e5b61d3a21190bb087))

- Implement framework-specific detection agents and sequential debate pipeline
  ([`67debfb`](https://github.com/prakharsingh/audit-packs/commit/67debfb87ac219bb2a9f1570b13684e5413449b2))

- Implement orchestration CLI and integration test running Checkov and Semgrep
  ([#8](https://github.com/prakharsingh/audit-packs/pull/8),
  [`8c43046`](https://github.com/prakharsingh/audit-packs/commit/8c4304681a89ffe97a45516690d40a2e19902e02))

- Implement OSCAL assessment results schema generation
  ([`558ee5a`](https://github.com/prakharsingh/audit-packs/commit/558ee5a3af1a3cc495ab352c63277d9588c7a630))

- Implement unified diff parser to resolve changed line ranges
  ([#3](https://github.com/prakharsingh/audit-packs/pull/3),
  [`a57357d`](https://github.com/prakharsingh/audit-packs/commit/a57357d6fa5a15dee28bd642b388472f66dd3754))

- Integrate debate pipeline, confidence gating, and coverage reporting
  ([`955b236`](https://github.com/prakharsingh/audit-packs/commit/955b236b8956f08bb3af624f200a705a8b73c7db))

- Normalize SARIF engine reports into standard Finding models
  ([#4](https://github.com/prakharsingh/audit-packs/pull/4),
  [`ff6b4b0`](https://github.com/prakharsingh/audit-packs/commit/ff6b4b033e72696215adc6e61e36d6896bb0050e))

- Package orchestrator as a Docker GitHub Action
  ([#9](https://github.com/prakharsingh/audit-packs/pull/9),
  [`184ec29`](https://github.com/prakharsingh/audit-packs/commit/184ec292d9fec3a8a4d147021e51eff09d96b1c5))

- Scaffold project metadata and define Finding/ControlFinding models for control mapping
  ([#2](https://github.com/prakharsingh/audit-packs/pull/2),
  [`fc7c860`](https://github.com/prakharsingh/audit-packs/commit/fc7c8600d5cb45a762834100757c1f3b059332bf))
