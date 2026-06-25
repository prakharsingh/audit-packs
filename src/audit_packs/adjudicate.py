"""AI ensemble adjudication for compliance findings.

IO boundary: makes HTTP calls to LLM provider APIs.
Pipeline: Detector → (Verifier ‖ Adversarial) → Judge (sequential with parallel Round 2).
Returns AdjudicationResult with float confidence scores.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml

from audit_packs.models import AdjudicationMode, AdjudicationResult, ControlFinding  # noqa: F401
from audit_packs.evidence import PRContext

log = logging.getLogger(__name__)

_CACHE_DIR = ".audit-cache"

_VALID_PROVIDERS = {"openai", "anthropic", "google", "ollama", "openai-compatible"}

_ROLE_DEFAULTS: dict[str, dict] = {
    "detector": {
        "provider": "openai",
        "model": "gpt-4o",
        "base_url": None,
        "api_key_env": "OPENAI_API_KEY",
    },
    "verifier": {
        "provider": "anthropic",
        "model": "claude-opus-4-5",
        "base_url": None,
        "api_key_env": "ANTHROPIC_API_KEY",
    },
    "adversarial": {
        "provider": "google",
        "model": "gemini-1.5-pro",
        "base_url": None,
        "api_key_env": "GOOGLE_API_KEY",
    },
    "judge": {
        "provider": "openai",
        "model": "gpt-4o",
        "base_url": None,
        "api_key_env": "OPENAI_API_KEY",
    },
}


# ---------------------------------------------------------------------------
# Model config loading
# ---------------------------------------------------------------------------


def load_model_config(config_path: str = "audit-models.yaml") -> dict:
    """Load model routing config; apply env var overrides. Returns per-role config dict."""
    config = {role: dict(defaults) for role, defaults in _ROLE_DEFAULTS.items()}

    if os.path.exists(config_path):
        try:
            with open(config_path) as fh:
                raw = yaml.safe_load(fh) or {}
        except Exception as exc:
            raise ValueError(f"Invalid YAML in {config_path!r}: {exc}") from exc

        for role in _ROLE_DEFAULTS:
            role_cfg = raw.get("models", {}).get(role, {})
            for key in ("provider", "model", "base_url", "api_key_env"):
                if key in role_cfg:
                    config[role][key] = role_cfg[key]

        for role in _ROLE_DEFAULTS:
            provider = config[role]["provider"]
            if provider not in _VALID_PROVIDERS:
                raise ValueError(f"Role {role!r}: unsupported provider {provider!r}")

    for role in _ROLE_DEFAULTS:
        env_prefix = role.upper()
        for key, env_suffix in [
            ("model", "MODEL"),
            ("provider", "PROVIDER"),
            ("base_url", "BASE_URL"),
        ]:
            val = os.environ.get(f"{env_prefix}_{env_suffix}", "")
            if val:
                config[role][key] = val

    return config


# ---------------------------------------------------------------------------
# Provider dispatch
# ---------------------------------------------------------------------------

_LLM_TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "15.0"))
_TIMEOUT = int(os.environ.get("THREAD_TIMEOUT", "60"))


def _call_with_retry(func, max_attempts=3, delay=2, backoff=2):
    attempt = 0
    while True:
        try:
            return func()
        except Exception as exc:
            attempt += 1
            if attempt >= max_attempts:
                log.error("API call failed after %d attempts: %s", max_attempts, exc)
                raise
            log.warning(
                "API call failed (attempt %d/%d), retrying in %ds: %s",
                attempt,
                max_attempts,
                delay,
                exc,
            )
            import time

            time.sleep(delay)
            delay *= backoff


def _clean_json_text(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        # Strip start block (e.g. ```json or ```)
        first_newline = text.find("\n")
        if first_newline != -1:
            text = text[first_newline:].strip()
        # Strip end block (```)
        if text.endswith("```"):
            text = text[:-3].strip()
    return text


def _call_role(role_cfg: dict, system_prompt: str, user_content: str) -> dict:
    """Call one LLM role and return parsed JSON dict with retry and timeout."""
    provider = role_cfg["provider"]
    model = role_cfg["model"]
    api_key_env = role_cfg.get("api_key_env") or ""
    base_url = role_cfg.get("base_url") or None
    api_key = os.environ.get(api_key_env, "") if api_key_env else ""

    def _execute():
        if provider in ("openai", "openai-compatible"):
            try:
                import openai
            except ImportError:
                raise ImportError(
                    "openai package is required for ADJUDICATION_MODE=advisory|enforce "
                    "with provider='openai'. Install with: pip install 'audit-packs[ai]'"
                ) from None

            client = openai.OpenAI(
                api_key=api_key or "dummy", base_url=base_url, timeout=_LLM_TIMEOUT
            )
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                response_format={"type": "json_object"},
                max_tokens=512,
            )
            return json.loads(resp.choices[0].message.content)

        if provider == "ollama":
            try:
                import openai
            except ImportError:
                raise ImportError(
                    "openai package is required for provider='ollama'. "
                    "Install with: pip install 'audit-packs[ai]'"
                ) from None

            client = openai.OpenAI(
                api_key="ollama",
                base_url=base_url or "http://localhost:11434/v1",
                timeout=_LLM_TIMEOUT,
            )
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                max_tokens=512,
            )
            return json.loads(resp.choices[0].message.content)

        if provider == "anthropic":
            try:
                import anthropic
            except ImportError:
                raise ImportError(
                    "anthropic package is required for ADJUDICATION_MODE=advisory|enforce "
                    "with provider='anthropic'. Install with: pip install 'audit-packs[ai]'"
                ) from None

            client = anthropic.Anthropic(api_key=api_key, timeout=_LLM_TIMEOUT)
            resp = client.messages.create(
                model=model,
                max_tokens=512,
                system=system_prompt,
                messages=[{"role": "user", "content": user_content}],
            )
            return json.loads(resp.content[0].text)

        if provider == "google":
            try:
                import google.generativeai as genai
            except ImportError:
                raise ImportError(
                    "google-generativeai package is required for ADJUDICATION_MODE=advisory|enforce "
                    "with provider='google'. Install with: pip install 'audit-packs[ai]'"
                ) from None

            genai.configure(api_key=api_key)
            gm = genai.GenerativeModel(
                model,
                system_instruction=system_prompt,
                generation_config={"response_mime_type": "application/json"},
            )
            resp = gm.generate_content(
                user_content, request_options={"timeout": _LLM_TIMEOUT}
            )
            cleaned = _clean_json_text(resp.text)
            return json.loads(cleaned)

        raise ValueError(f"Unknown provider: {provider!r}")

    return _call_with_retry(_execute)


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


def _cache_key(cf: ControlFinding) -> str:
    raw = f"{cf.finding.check_id}|{cf.framework}|{cf.finding.file}|{cf.control_id}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _load_cache(cf: ControlFinding) -> AdjudicationResult | None:
    if os.environ.get("AUDIT_CACHE", "on") == "off":
        return None
    path = os.path.join(_CACHE_DIR, f"{_cache_key(cf)}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path) as fh:
            data = json.load(fh)
        return AdjudicationResult(
            control_finding=cf,
            detector_score=data["detector_score"],
            verifier_argument=data["verifier_argument"],
            adversarial_argument=data["adversarial_argument"],
            judge_score=data["judge_score"],
            model_consensus=data["model_consensus"],
            rationale=data["rationale"],
        )
    except Exception:
        return None


def _save_cache(cf: ControlFinding, result: AdjudicationResult) -> None:
    if os.environ.get("AUDIT_CACHE", "on") == "off":
        return
    os.makedirs(_CACHE_DIR, exist_ok=True)
    path = os.path.join(_CACHE_DIR, f"{_cache_key(cf)}.json")
    try:
        with open(path, "w") as fh:
            json.dump(
                {
                    "detector_score": result.detector_score,
                    "verifier_argument": result.verifier_argument,
                    "adversarial_argument": result.adversarial_argument,
                    "judge_score": result.judge_score,
                    "model_consensus": result.model_consensus,
                    "rationale": result.rationale,
                },
                fh,
            )
    except Exception as exc:
        log.debug("adjudicate: cache write failed: %s", exc)


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------


def _finding_context(cf: ControlFinding, pr_context: PRContext | None) -> str:
    f = cf.finding
    path_text = ""
    if f.evidence_path:
        path_text = "\nEvidence path:\n" + "\n".join(
            f"  {i+1}. [{node.file}:{node.line}] {node.snippet}  ← {node.description}"
            for i, node in enumerate(f.evidence_path)
        )
    flow_text = ""
    if f.doc_context:
        flow_text = f"\nDoc comment: {f.doc_context}"
    pr_text = ""
    if pr_context:
        pr_text = f"\nPR context: {pr_context.pr_body}" + (
            f"\nRecent commits: {'; '.join(pr_context.commit_messages)}"
            if pr_context.commit_messages
            else ""
        )
    return (
        f"Control: {cf.control_id} — {cf.control_title}\n"
        f"Framework: {cf.framework}\n"
        f"Finding: {f.check_id} on {f.file}:{f.line} ({f.engine})\n"
        f"Severity: {f.severity}\n"
        f"Message: {f.message}\n"
        f"Evidence: {f.evidence}" + path_text + flow_text + pr_text
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def adjudicate(
    cf: ControlFinding,
    pr_context: PRContext | None,
    mode: AdjudicationMode,
    model_config: dict,
) -> AdjudicationResult:
    """Run the 4-role ensemble for one ControlFinding. Returns AdjudicationResult."""
    if mode is AdjudicationMode.OFF:
        return AdjudicationResult(
            control_finding=cf,
            detector_score=1.0,
            verifier_argument="",
            adversarial_argument="",
            judge_score=1.0,
            model_consensus=1.0,
            rationale="adjudication disabled",
        )

    cached = _load_cache(cf)
    if cached is not None:
        return cached

    ctx = _finding_context(cf, pr_context)

    # --- Round 1: Detector ---
    detector_score = 0.5
    detector_assessment = "no assessment"
    try:
        det = _call_role(
            model_config["detector"],
            f"You are a {cf.framework} compliance expert. Assess this finding. "
            'Return JSON: {"confidence": <0.0-1.0>, "assessment": "<2-3 sentences>"}',
            ctx,
        )
        detector_score = float(det.get("confidence", 0.5))
        detector_assessment = det.get("assessment", "")
    except Exception as exc:
        log.warning("adjudicate: detector failed (%s); using neutral score", exc)
        result = AdjudicationResult(
            control_finding=cf,
            detector_score=0.5,
            verifier_argument="",
            adversarial_argument="",
            judge_score=0.5,
            model_consensus=0.5,
            rationale="model_confidence_unavailable",
        )
        return result

    round2_ctx = (
        ctx
        + f"\n\nDetector assessment (score {detector_score:.2f}): {detector_assessment}"
    )

    # --- Round 2: Verifier + Adversarial (parallel) ---
    verifier_arg = ""
    adversarial_arg = ""

    def _run_verifier():
        return _call_role(
            model_config["verifier"],
            f"You are a strict {cf.framework} compliance auditor. Argue why the following finding "
            'IS a genuine violation. Return JSON: {"argument": "<arg>", "strength": <0.0-1.0>}',
            round2_ctx,
        )

    def _run_adversarial():
        return _call_role(
            model_config["adversarial"],
            "You are defence counsel. Argue why this finding is a FALSE POSITIVE. "
            'Return JSON: {"argument": "<arg>", "strength": <0.0-1.0>}',
            round2_ctx,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            executor.submit(_run_verifier): "verifier",
            executor.submit(_run_adversarial): "adversarial",
        }
        try:
            for fut in as_completed(futures, timeout=_TIMEOUT):
                role = futures[fut]
                try:
                    res = fut.result()
                    if role == "verifier":
                        verifier_arg = res.get("argument", "")
                    else:
                        adversarial_arg = res.get("argument", "")
                except Exception as exc:
                    log.warning("adjudicate: %s failed (%s)", role, exc)
        except TimeoutError:
            log.warning(
                "adjudicate: Round 2 parallel execution timed out after %d seconds",
                _TIMEOUT,
            )

    # --- Round 3: Judge ---
    judge_score = detector_score
    rationale = "judge fallback: using detector score"
    try:
        judge_ctx = (
            f"Detector score: {detector_score:.2f}\n"
            f"Prosecution (verifier): {verifier_arg or '(unavailable)'}\n"
            f"Defence (adversarial): {adversarial_arg or '(unavailable)'}\n\n" + ctx
        )
        jud = _call_role(
            model_config["judge"],
            f"You are a senior {cf.framework} compliance judge. Weigh the evidence and return "
            'a final confidence score. Return JSON: {"confidence": <0.0-1.0>, "rationale": "<one sentence>"}',
            judge_ctx,
        )
        judge_score = float(jud.get("confidence", detector_score))
        rationale = jud.get("rationale", "")
    except Exception as exc:
        log.warning("adjudicate: judge failed (%s); using detector score", exc)

    result = AdjudicationResult(
        control_finding=cf,
        detector_score=detector_score,
        verifier_argument=verifier_arg,
        adversarial_argument=adversarial_arg,
        judge_score=judge_score,
        model_consensus=judge_score,
        rationale=rationale,
    )
    _save_cache(cf, result)
    return result
