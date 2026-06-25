"""Verify that missing AI provider packages produce actionable error messages."""

import sys
import pytest
from unittest.mock import patch


def test_openai_missing_gives_actionable_error():
    """ModuleNotFoundError for openai must include install instructions."""
    from audit_packs.adjudicate import _call_role

    role_cfg = {
        "provider": "openai",
        "model": "gpt-4o",
        "api_key_env": "OPENAI_API_KEY",
        "base_url": None,
    }

    # Simulate openai not being installed
    with patch.dict(sys.modules, {"openai": None}):
        with pytest.raises(ImportError, match="pip install 'audit-packs\\[ai\\]'"):
            _call_role(role_cfg, "system", "user")


def test_anthropic_missing_gives_actionable_error():
    from audit_packs.adjudicate import _call_role

    role_cfg = {
        "provider": "anthropic",
        "model": "claude-opus-4-5",
        "api_key_env": "ANTHROPIC_API_KEY",
        "base_url": None,
    }
    with patch.dict(sys.modules, {"anthropic": None}):
        with pytest.raises(ImportError, match="pip install 'audit-packs\\[ai\\]'"):
            _call_role(role_cfg, "system", "user")


def test_google_missing_gives_actionable_error():
    from audit_packs.adjudicate import _call_role

    role_cfg = {
        "provider": "google",
        "model": "gemini-1.5-pro",
        "api_key_env": "GOOGLE_API_KEY",
        "base_url": None,
    }
    with patch.dict(sys.modules, {"google.generativeai": None, "google": None}):
        with pytest.raises(ImportError, match="pip install 'audit-packs\\[ai\\]'"):
            _call_role(role_cfg, "system", "user")
