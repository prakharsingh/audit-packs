# Skill Registry

Read this file first. Full `SKILL.md` contents load only when a skill's
triggers match the current task. Machine-readable equivalent:
`skills/_manifest.jsonl`.

## skillforge
Creates new skills from observed patterns and recurring tasks.
Triggers: "create skill", "new skill", "I keep doing this manually"

## memory-manager
Reads, scores, and consolidates memory. Runs reflection cycles.
Triggers: "reflect", "what did I learn", "compress memory"

## git-proxy
All git operations with safety constraints.
Triggers: "commit", "push", "branch", "merge", "rebase"
Constraints: never force push to main; run tests before push.

## debug-investigator
Systematic debugging: reproduce, isolate, hypothesize, verify.
Triggers: "debug", "why is this failing", "investigate"

## deploy-checklist
Pre-deployment verification against a structured checklist.
Triggers: "deploy", "ship", "release", "go live"
Constraints: all tests passing, no unresolved TODOs in diff,
requires human approval for production.

## data-layer
Cross-harness activity monitoring and dashboard exports. Use it as the
injected dashboard surface when users ask naturally.
Triggers: "data layer", "dashboard", "show me the dashboard",
"what did my agents do", "agent analytics", "agent status", "resource usage",
"usage report", "cron monitoring", "daily report", "tokens",
"terminal dashboard", "TUI"
Constraints: local-only by default; no screenshot delivery without explicit user
approval; do not commit private `.agent/data-layer/` exports.

## data-flywheel
Turns approved, redacted runs into reusable local artifacts: trace records,
context cards, eval cases, training-ready JSONL, and flywheel metrics.
Triggers: "data flywheel", "trace to train", "training traces",
"context cards", "eval cases", "approved runs", "vertical intelligence"
Constraints: local-only by default; human-approved runs only; redaction required
before trainable; does not train models.

## brain
Connects agentic-stack projects to the external Brain CLI and MCP server for
git-backed long-term memory shared across harnesses.
Triggers: "brain", "long-term memory", "shared memory", "cross-agent memory",
"mcp memory", "remember across tools", "git-backed memory"
Constraints: Brain is external; check availability before use, do not store
secrets, and use `brain_bridge.py ask` before saving new durable notes.

## design-md
Uses a root `DESIGN.md` as the portable visual system contract for
Google Stitch workflows. Loads only when `DESIGN.md` exists at the
project root.
Triggers: "DESIGN.md", "design.md", "Google Stitch", "design tokens",
"design system", "visual design"
Preconditions: DESIGN.md exists at project root.
Constraints: prefer DESIGN.md tokens over invented values, do not modify
DESIGN.md unless the user explicitly asks, preserve unknown sections when
an edit IS authorised, validate with `npx @google/design.md lint DESIGN.md`
when available.

## tldraw
Draw, diagram, sketch, or lay out ideas on a live tldraw canvas.
Worthwhile drawings snapshot into this skill's local store
(`skills/tldraw/store.py`) for recall across sessions.
Triggers: "draw", "diagram", "sketch", "wireframe", "flowchart",
"mind-map", "visualize", "whiteboard"
Constraints: get_canvas before edits; max 200 shapes per create_shape call.
Requires: tldraw MCP server wired in the harness's MCP config; user has
http://localhost:3030 open. Opt-in via `.features.json` (`tldraw: true`).

## engineering-ai-data-remediation-engineer
Fixes your broken data with surgical AI precision — no rows left behind.
Triggers: "remediate data", "fix bad data", "data anomalies", "data remediation", "bad data pipeline", "self-healing data", "data healing", "data anomaly"
Constraints: intercept bad data, generate deterministic fix logic, guarantee zero data loss

## engineering-ai-engineer
Turns ML models into production features that actually scale.
Triggers: "ai engineer", "machine learning", "ml model", "deep learning", "vector database", "model training", "inference api", "hugging face", "rag system"
Constraints: always implement bias testing, ensure model transparency, include privacy-preserving techniques, build content safety measures

## engineering-autonomous-optimization-architect
The system governor that makes things faster without bankrupting you.
Triggers: "optimization architect", "shadow test", "shadow testing", "api performance", "runaway costs", "cost guardrails", "circuit breaker", "semantic routing"
Constraints: enforce strict financial and security guardrails, shadow-test APIs for performance, prevent runaway costs

## engineering-backend-architect
Designs the systems that hold everything up — databases, APIs, cloud, scale.
Triggers: "backend architect", "system design", "database architecture", "server-side application", "api development", "scalable system", "microservices"
Constraints: focus on scalability, robust and secure design, optimize performance

## engineering-code-reviewer
Reviews code like a mentor, not a gatekeeper. Every comment teaches something.
Triggers: "code reviewer", "review code", "code review", "pr review", "pull request review"
Constraints: be specific with line numbers, explain reasoning, suggest instead of demand, prioritize comments, praise good code

## engineering-codebase-onboarding-engineer
Gets new developers productive faster by reading the code, tracing the paths, and stating the facts. Nothing extra.
Triggers: "onboarding engineer", "understand codebase", "code path trace", "codebase walkthrough", "new codebase"
Constraints: state only facts grounded in code, no assumptions, trace execution paths objectively

## engineering-data-engineer
Builds the pipelines that turn raw data into trusted, analytics-ready assets.
Triggers: "data engineer", "data pipeline", "lakehouse", "etl", "elt", "apache spark", "dbt"
Constraints: build reliable data pipelines, ensure data trust, optimize throughput

## engineering-database-optimizer
Indexes, query plans, and schema design — databases that don't wake you at 3am.
Triggers: "database optimizer", "query optimization", "indexing strategy", "schema design", "database tuning", "database performance"
Constraints: explain query plans, optimize indexing, design clean schemas

## engineering-devops-automator
Automates infrastructure so your team ships faster and sleeps better.
Triggers: "devops", "infrastructure automation", "ci/cd pipeline", "cloud operations", "devops automator"
Constraints: automate infrastructure safely, optimize build times, handle credentials securely

## engineering-embedded-firmware-engineer
Writes production-grade firmware for hardware that can't afford to crash.
Triggers: "firmware engineer", "bare-metal", "rtos", "esp32", "platformio", "arduino", "microcontroller", "embedded firmware"
Constraints: write safety-critical code, manage memory footprint, handle real-time constraints

## engineering-frontend-developer
Builds responsive, accessible web apps with pixel-perfect precision.
Triggers: "frontend developer", "web UI", "react developer", "vue developer", "frontend performance", "ui implementation"
Constraints: ensure accessibility, pixel-perfect implementation, optimize page speed

## engineering-git-workflow-master
Clean history, atomic commits, and branches that tell a story.
Triggers: "git workflow", "branching strategy", "version control", "git rebase", "git worktree", "conventional commits"
Constraints: atomic commits, clean branching history, follow conventional commits style

## engineering-senior-developer
Premium full-stack craftsperson — Laravel, Livewire, Three.js, advanced CSS.
Triggers: "senior developer", "laravel", "livewire", "fluxui", "three.js", "advanced css"
Constraints: premium full-stack implementation, modern UI animations, optimized assets

## engineering-software-architect
Designs systems that survive the team that built them. Every decision has a trade-off — name it.
Triggers: "software architect", "architectural pattern", "domain-driven design", "architectural decision", "system design tradeoffs"
Constraints: explicitly identify trade-offs, ensure long-term maintainability, apply domain-driven design

## engineering-sre
Reliability is a feature. Error budgets fund velocity — spend them wisely.
Triggers: "sre", "site reliability", "slo", "error budget", "observability", "chaos engineering", "toil reduction"
Constraints: manage error budgets, design for observability, reduce operational toil

## engineering-technical-writer
Writes the docs that developers actually read and use.
Triggers: "technical writer", "developer documentation", "api reference", "readme file", "writing tutorials", "technical writing"
Constraints: clear and accurate documentation, developers-first perspective, well-structured markdown

## engineering-threat-detection-engineer
Builds the detection layer that catches attackers after they bypass prevention.
Triggers: "threat detection", "detection engineer", "siem rule", "mitre att&ck", "threat hunting", "alert tuning", "detection-as-code"
Constraints: map to MITRE ATT&CK, minimize false positives, use detection-as-code approach
