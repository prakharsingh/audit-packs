# Examples

Copy-paste starting points for common audit-packs configurations.

## Workflows (`workflows/`)

Ready-to-use GitHub Actions workflow files. Copy to `.github/workflows/` in your repo.

| File | Use case |
|---|---|
| `basic.yml` | Minimal setup — NIST 800-53 + SOC 2, gate on high |
| `soc2-hipaa.yml` | SOC 2 + HIPAA for health-data SaaS; uploads OSCAL evidence |
| `nist-fedramp.yml` | NIST 800-53 + FedRAMP Moderate; gate on medium; long-retention artifacts |
| `pci-iso27001.yml` | PCI-DSS + ISO 27001 + org-policy for fintech |
| `with-codeql.yml` | SAST + IaC in one compliance view via CodeQL integration |
| `with-adjudication.yml` | AI adjudication enabled in enforce mode; suppresses low-confidence findings |
| `scheduled-posture.yml` | Nightly full-posture scan; no PR gate; produces OSCAL + coverage matrix |

## Model routing (`audit-models/`)

Drop-in `audit-models.yaml` files for the AI adjudication ensemble. Set `models-config:` in your workflow to point at one of these, or copy it to your repo root as `audit-models.yaml`.

| File | Providers | Notes |
|---|---|---|
| `openai-only.yaml` | OpenAI | Single-provider; simplest secret management |
| `anthropic-only.yaml` | Anthropic | Single-provider; judge uses Opus for higher accuracy |
| `local-ollama.yaml` | Ollama (local) | Zero external API calls; requires Ollama on the runner |
| `mixed-cost-optimized.yaml` | OpenAI + Anthropic + Google | Cheap models for detection/verification; stronger judge |

## Org-policy packs (`org-policy/`)

Industry-specific `org-policy.yaml` templates that layer internal controls on top of the standard framework packs. Copy to `packs/org-policy.yaml` and add `org-policy` to your `frameworks:` input.

| File | Industry | Pairs with |
|---|---|---|
| `saas-startup.yaml` | General SaaS | `nist-800-53,soc2` |
| `fintech.yaml` | Fintech / payments | `pci-dss,iso27001` |
| `healthcare.yaml` | Health tech / HIPAA-covered | `hipaa,soc2` |
