"""Tests for the rewritten 4-role adjudicate.py."""

import json
import pytest
from unittest.mock import MagicMock, patch
from audit_packs_core.models import (
    Finding,
    ControlFinding,
    AdjudicationMode,
    AdjudicationResult,
)
from audit_packs_evidence.evidence import PRContext
from audit_packs_ai.adjudicate import adjudicate, load_model_config, AdjudicationMode  # noqa


def _cf():
    f = Finding(
        "CKV_AWS_19",
        "checkov",
        "main.tf",
        5,
        "high",
        "S3 not encrypted",
        "encrypted=false",
    )
    return ControlFinding(f, "gdpr", "SC-28", "Protection of Information at Rest")


def _pr():
    return PRContext(
        pr_body="Fix S3 encryption", commit_messages=("fix: enable S3 encryption",)
    )


_DEFAULT_CONFIG = {
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
    "challenger": {
        "provider": "google",
        "model": "gemini-1.5-pro",
        "base_url": None,
        "api_key_env": "GOOGLE_API_KEY",
    },
    "consensus": {
        "provider": "openai",
        "model": "gpt-4o",
        "base_url": None,
        "api_key_env": "OPENAI_API_KEY",
    },
}


class TestAdjudicateModeOff:
    @pytest.fixture(autouse=True)
    def disable_cache(self, monkeypatch):
        monkeypatch.setenv("AUDIT_CACHE", "off")

    def test_returns_neutral_result_when_mode_off(self):
        result = adjudicate(_cf(), None, AdjudicationMode.OFF, _DEFAULT_CONFIG)
        assert isinstance(result, AdjudicationResult)
        assert result.model_consensus == 1.0

    def test_mode_off_does_not_call_any_llm(self):
        with patch("audit_packs_ai.adjudicate._call_role") as mock:
            adjudicate(_cf(), None, AdjudicationMode.OFF, _DEFAULT_CONFIG)
            mock.assert_not_called()


class TestAdjudicatePipeline:
    @pytest.fixture(autouse=True)
    def disable_cache(self, monkeypatch):
        monkeypatch.setenv("AUDIT_CACHE", "off")

    def _mock_call_role(self, role_responses: dict):
        """Returns a mock that returns different JSON per system_prompt substring."""
        responses_list = []
        for key in ["detector", "verifier", "challenger", "consensus"]:
            if key in role_responses:
                responses_list.append(role_responses[key])

        call_count = [0]

        def side_effect(role_cfg, system_prompt, user_content):
            idx = call_count[0]
            call_count[0] += 1
            return responses_list[idx % len(responses_list)]

        return side_effect

    def test_sequential_pipeline_calls_four_roles(self, monkeypatch):
        calls = []

        def mock_call(role_cfg, system_prompt, user_content):
            if "compliance expert" in system_prompt:
                calls.append("detector")
                return {"confidence": 0.8, "assessment": "Likely violation"}
            elif (
                "prosecution" in system_prompt
                or "IS a genuine violation" in system_prompt
            ):
                calls.append("verifier")
                return {"argument": "data stored plaintext", "strength": 0.9}
            elif "defence" in system_prompt or "FALSE POSITIVE" in system_prompt:
                calls.append("challenger")
                return {"argument": "this is a test bucket", "strength": 0.3}
            elif "judge" in system_prompt:
                calls.append("consensus")
                return {"confidence": 0.75, "rationale": "Evidence supports violation"}
            return {"confidence": 0.5, "rationale": "fallback"}

        with patch("audit_packs_ai.adjudicate._call_role", side_effect=mock_call):
            result = adjudicate(_cf(), _pr(), AdjudicationMode.ENFORCE, _DEFAULT_CONFIG)

        assert "detector" in calls
        assert "verifier" in calls
        assert "challenger" in calls
        assert "consensus" in calls
        assert result.consensus_score == pytest.approx(0.75)
        assert result.model_consensus == result.consensus_score

    def test_detector_failure_returns_neutral(self, monkeypatch):
        with patch(
            "audit_packs_ai.adjudicate._call_role", side_effect=Exception("API down")
        ):
            result = adjudicate(_cf(), _pr(), AdjudicationMode.ENFORCE, _DEFAULT_CONFIG)
        assert result.model_consensus == 0.5

    def test_judge_failure_falls_back_to_detector_score(self, monkeypatch):
        call_count = [0]

        def mock_call(role_cfg, system_prompt, user_content):
            call_count[0] += 1
            if call_count[0] == 1:
                return {"confidence": 0.82, "assessment": "Violation found"}
            if call_count[0] in (2, 3):
                return {"argument": "arg", "strength": 0.5}
            raise Exception("Judge down")

        with patch("audit_packs_ai.adjudicate._call_role", side_effect=mock_call):
            result = adjudicate(_cf(), _pr(), AdjudicationMode.ENFORCE, _DEFAULT_CONFIG)
        assert result.model_consensus == pytest.approx(0.82)


class TestLoadModelConfig:
    def test_returns_defaults_when_file_missing(self, tmp_path):
        cfg = load_model_config(str(tmp_path / "nonexistent.yaml"))
        assert cfg["detector"]["model"] == "gpt-4o"
        assert cfg["verifier"]["provider"] == "anthropic"

    def test_yaml_file_overrides_role(self, tmp_path):
        config_path = tmp_path / "audit-models.yaml"
        config_path.write_text(
            "models:\n  detector:\n    provider: openai\n    model: gpt-5\n"
        )
        cfg = load_model_config(str(config_path))
        assert cfg["detector"]["model"] == "gpt-5"
        assert cfg["verifier"]["provider"] == "anthropic"

    def test_invalid_yaml_raises_value_error(self, tmp_path):
        config_path = tmp_path / "bad.yaml"
        config_path.write_text("models: [\n  invalid: yaml: [\n")
        with pytest.raises(ValueError, match="Invalid YAML"):
            load_model_config(str(config_path))

    def test_unknown_provider_raises_value_error(self, tmp_path):
        config_path = tmp_path / "audit-models.yaml"
        config_path.write_text(
            "models:\n  detector:\n    provider: unknown_llm\n    model: x\n"
        )
        with pytest.raises(ValueError, match="unsupported provider"):
            load_model_config(str(config_path))

    def test_env_var_overrides_yaml(self, tmp_path, monkeypatch):
        config_path = tmp_path / "audit-models.yaml"
        config_path.write_text("models:\n  detector:\n    model: gpt-4o\n")
        monkeypatch.setenv("DETECTOR_MODEL", "gpt-5-turbo")
        cfg = load_model_config(str(config_path))
        assert cfg["detector"]["model"] == "gpt-5-turbo"


class TestCaching:
    def test_cache_hit_skips_llm_calls(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AUDIT_CACHE", "on")
        cache_dir = tmp_path / ".audit-cache"
        cache_dir.mkdir()

        cached = {
            "detector_score": 0.9,
            "verifier_argument": "v",
            "challenger_argument": "a",
            "consensus_score": 0.9,
            "model_consensus": 0.9,
            "rationale": "cached",
        }
        cf = _cf()
        import hashlib

        key = hashlib.sha256(
            f"{cf.finding.check_id}|{cf.framework}|{cf.finding.file}|{cf.control_id}".encode()
        ).hexdigest()
        (cache_dir / f"{key}.json").write_text(json.dumps(cached))

        with patch("audit_packs_ai.adjudicate._CACHE_DIR", str(cache_dir)):
            with patch("audit_packs_ai.adjudicate._call_role") as mock:
                result = adjudicate(
                    cf, _pr(), AdjudicationMode.ENFORCE, _DEFAULT_CONFIG
                )
                mock.assert_not_called()
        assert result.model_consensus == pytest.approx(0.9)


def test_call_role_google_handles_markdown_and_sets_mime_type(monkeypatch):
    import sys

    mock_genai = MagicMock()
    mock_google = MagicMock()
    mock_google.generativeai = mock_genai
    sys.modules["google"] = mock_google
    sys.modules["google.generativeai"] = mock_genai

    from audit_packs_ai.adjudicate import _call_role

    role_cfg = {
        "provider": "google",
        "model": "gemini-1.5-pro",
        "api_key_env": "GOOGLE_API_KEY",
    }

    mock_resp = MagicMock()
    # Mock markdown wrapped JSON
    mock_resp.text = '```json\n{\n  "confidence": 0.82\n}\n```'

    mock_model = MagicMock()
    mock_model.generate_content.return_value = mock_resp
    mock_genai.GenerativeModel.return_value = mock_model

    res = _call_role(role_cfg, "system prompt", "user content")
    assert res == {"confidence": 0.82}

    mock_genai.GenerativeModel.assert_called_once_with(
        "gemini-1.5-pro",
        system_instruction="system prompt",
        generation_config={"response_mime_type": "application/json"},
    )


def test_adjudicate_verifier_adversarial_timeout_handling(monkeypatch):
    import time
    from audit_packs_ai.adjudicate import adjudicate
    import audit_packs_ai.adjudicate

    # Disable cache and set timeout to a very small value to trigger it quickly
    monkeypatch.setenv("AUDIT_CACHE", "off")
    monkeypatch.setattr(audit_packs_ai.adjudicate, "_TIMEOUT", 0.01, raising=False)

    def mock_call(role_cfg, system_prompt, user_content):
        if "compliance expert" in system_prompt:
            return {"confidence": 0.8, "assessment": "Likely violation"}
        elif "compliance auditor" in system_prompt or "FALSE POSITIVE" in system_prompt:
            time.sleep(0.1)  # longer than _TIMEOUT
            return {"argument": "too slow"}
        elif "judge" in system_prompt:
            return {"confidence": 0.75, "rationale": "Evidence supports violation"}
        return {}

    with patch("audit_packs_ai.adjudicate._call_role", side_effect=mock_call):
        result = adjudicate(_cf(), _pr(), AdjudicationMode.ENFORCE, _DEFAULT_CONFIG)
        # If timeout works, it should fallback to empty string arguments
        assert result.verifier_argument == ""
        assert result.challenger_argument == ""
