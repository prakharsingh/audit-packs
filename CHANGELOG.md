# CHANGELOG


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
