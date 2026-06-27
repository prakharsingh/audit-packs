FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY packages ./packages
COPY packs ./packs
COPY rules ./rules
ARG INSTALL_AI=false
RUN pip install --no-cache-dir \
    -e packages/core \
    -e packages/mapping \
    -e packages/evidence \
    -e packages/ai \
    -e packages/action \
    checkov semgrep \
    && if [ "$INSTALL_AI" = "true" ]; then pip install --no-cache-dir -e "packages/ai[ai]"; fi
# trivy v0.69.2 — bump version here to upgrade
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin v0.69.2
# tfsec v1.28.6 — bump version here to upgrade
RUN curl -sfL "https://github.com/aquasecurity/tfsec/releases/download/v1.28.6/tfsec-linux-amd64" \
    -o /usr/local/bin/tfsec && chmod +x /usr/local/bin/tfsec
# gitleaks v8.18.2 — bump version here to upgrade
RUN curl -sfL "https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks
ENV PACKS_DIR=/app/packs RULES_PATH=/app/rules
ENTRYPOINT ["python", "-m", "audit_packs_action.cli"]
