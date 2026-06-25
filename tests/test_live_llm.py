import http.server
import importlib.util
import socketserver
import threading
import json
from unittest.mock import patch
import pytest
from audit_packs.models import (
    Finding,
    ControlFinding,
    AdjudicationMode,
    AdjudicationResult,
)
from audit_packs.evidence import PRContext
from audit_packs.adjudicate import adjudicate


pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("openai") is None,
    reason="openai package not installed — skipping live LLM tests",
)

# Global variable to configure mock server behavior dynamically
server_fail_verifier = False


class MockLLMHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_POST(self):
        global server_fail_verifier
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        req = json.loads(post_data.decode("utf-8"))

        messages = req.get("messages", [])
        system_prompt = next(
            (m["content"] for m in messages if m["role"] == "system"), ""
        )

        # Simulate verifier failure if requested
        if server_fail_verifier and (
            "prosecution" in system_prompt or "auditor" in system_prompt
        ):
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal Server Error")
            return

        # Map role responses based on system prompt checks
        response_data = {}
        if "expert" in system_prompt:
            response_data = {
                "confidence": 0.85,
                "assessment": "Mock detector says this is a violation.",
            }
        elif "prosecution" in system_prompt or "auditor" in system_prompt:
            response_data = {
                "argument": "Mock verifier argues it violates policies.",
                "strength": 0.9,
            }
        elif "defence" in system_prompt:
            response_data = {
                "argument": "Mock adversarial argues it is test code.",
                "strength": 0.3,
            }
        elif "judge" in system_prompt:
            response_data = {
                "confidence": 0.78,
                "rationale": "Mock judge rules it is a real violation.",
            }
        else:
            response_data = {"confidence": 0.5, "rationale": "fallback"}

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        resp = {
            "choices": [
                {"message": {"role": "assistant", "content": json.dumps(response_data)}}
            ]
        }
        self.wfile.write(json.dumps(resp).encode("utf-8"))


class MockLLMServer:
    def __init__(self):
        # Bind to port 0 so the OS assigns a free port atomically, avoiding TOCTOU race
        self.server = socketserver.TCPServer(("127.0.0.1", 0), MockLLMHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture(scope="module")
def mock_server():
    server = MockLLMServer()
    server.start()
    yield server
    server.stop()


@pytest.fixture()
def isolated_cache(tmp_path):
    """Redirect adjudicate's cache to a temporary directory for test isolation."""
    with patch("audit_packs.adjudicate._CACHE_DIR", str(tmp_path)):
        yield tmp_path


def test_live_llm_debate_and_caching(mock_server, isolated_cache):
    global server_fail_verifier
    server_fail_verifier = False

    # 1. Setup config pointing to mock server
    base_url = f"http://127.0.0.1:{mock_server.port}/v1"
    model_config = {
        "detector": {
            "provider": "openai",
            "model": "mock-detector",
            "base_url": base_url,
            "api_key_env": "MOCK_KEY",
        },
        "verifier": {
            "provider": "openai",
            "model": "mock-verifier",
            "base_url": base_url,
            "api_key_env": "MOCK_KEY",
        },
        "adversarial": {
            "provider": "openai",
            "model": "mock-adversarial",
            "base_url": base_url,
            "api_key_env": "MOCK_KEY",
        },
        "judge": {
            "provider": "openai",
            "model": "mock-judge",
            "base_url": base_url,
            "api_key_env": "MOCK_KEY",
        },
    }

    finding = Finding(
        "CKV_AWS_19",
        "checkov",
        "main.tf",
        11,
        "high",
        "S3 encryption missing",
        "snippet",
    )
    cf = ControlFinding(finding, "gdpr", "SC-28", "Protection at Rest")
    pr_context = PRContext("Clean up config files", ("fix: s3 rules",))

    # 2. Run adjudication via mock server (no cache yet)
    result = adjudicate(cf, pr_context, AdjudicationMode.ENFORCE, model_config)
    assert isinstance(result, AdjudicationResult)
    assert result.detector_score == 0.85
    assert result.judge_score == 0.78
    assert result.model_consensus == 0.78
    assert "Mock verifier" in result.verifier_argument
    assert "Mock adversarial" in result.adversarial_argument

    # 3. Test Cache Hit: shutdown / make server fail verifier, and run again.
    # It must return cached result successfully without hitting mock server.
    server_fail_verifier = True
    try:
        result_cached = adjudicate(
            cf, pr_context, AdjudicationMode.ENFORCE, model_config
        )
        assert result_cached.model_consensus == 0.78
        assert "Mock verifier" in result_cached.verifier_argument
    finally:
        server_fail_verifier = False


def test_live_llm_fallback_on_role_failure(mock_server, isolated_cache):
    global server_fail_verifier
    # Enable verifier failure
    server_fail_verifier = True

    base_url = f"http://127.0.0.1:{mock_server.port}/v1"
    model_config = {
        "detector": {
            "provider": "openai",
            "model": "mock-detector",
            "base_url": base_url,
            "api_key_env": "MOCK_KEY",
        },
        "verifier": {
            "provider": "openai",
            "model": "mock-verifier",
            "base_url": base_url,
            "api_key_env": "MOCK_KEY",
        },
        "adversarial": {
            "provider": "openai",
            "model": "mock-adversarial",
            "base_url": base_url,
            "api_key_env": "MOCK_KEY",
        },
        "judge": {
            "provider": "openai",
            "model": "mock-judge",
            "base_url": base_url,
            "api_key_env": "MOCK_KEY",
        },
    }

    # Use unique checking parameters so it doesn't hit cache
    finding = Finding(
        "CKV_AWS_20", "checkov", "main.tf", 22, "high", "S3 public read", "snippet2"
    )
    cf = ControlFinding(finding, "gdpr", "SC-28", "Protection at Rest")
    pr_context = PRContext("Other PR", ("other commit",))

    # Run adjudication. Since verifier fails (500), verifier_argument will be empty,
    # but the judge should still proceed and output judge_score.
    try:
        result = adjudicate(cf, pr_context, AdjudicationMode.ENFORCE, model_config)
        assert isinstance(result, AdjudicationResult)
        assert result.detector_score == 0.85
        assert result.verifier_argument == ""  # verifier failed
        assert (
            "Mock adversarial" in result.adversarial_argument
        )  # adversarial succeeded
        assert result.judge_score == 0.78
        assert result.model_consensus == 0.78
    finally:
        server_fail_verifier = False
