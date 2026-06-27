import tempfile
import os
import yaml
from audit_packs_evidence.agents import (
    DetectionAgent,
    NoOpAgent,
    DataFlowAgent,
    GDPRAgent,
    HIPAAAgent,
    SOC2Agent,
    FedRAMPAgent,
    OrgPolicyAgent,
    Nist80053Agent,
    build_agents,
)


def test_noop_agent_returns_empty_sarif():
    agent = NoOpAgent()
    result = agent.detect({"main.tf": "resource..."})
    assert result == {"runs": []}


def test_noop_agent_framework_is_noop():
    assert NoOpAgent.framework == "noop"


def test_noop_agent_is_detection_agent():
    assert isinstance(NoOpAgent(), DetectionAgent)


def test_noop_agent_accepts_empty_changed_files():
    agent = NoOpAgent()
    assert agent.detect({}) == {"runs": []}


def test_build_agents_returns_correct_agents():
    agents = build_agents(["gdpr", "hipaa"], "/app/packs")
    frameworks = {a.framework for a in agents}
    assert "dataflow" in frameworks
    assert "gdpr" in frameworks
    assert "hipaa" in frameworks
    assert "soc2" not in frameworks


def test_dataflow_agent_detects_unprotected_flow():
    code = """def handle_request(request):
    user_data = request.form.get("ssn")
    db.session.add(user_data)
"""
    agent = DataFlowAgent()
    sarif = agent.detect({"main.py": code})
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "DFA-001"
    assert "locations" in results[0]
    assert len(results[0]["codeFlows"][0]["threadFlows"][0]["locations"]) == 2


def test_dataflow_agent_ignores_protected_flow():
    code = """def handle_request(request):
    user_data = request.form.get("ssn")
    encrypted = encrypt(user_data)
    db.session.add(encrypted)
"""
    agent = DataFlowAgent()
    sarif = agent.detect({"main.py": code})
    results = sarif["runs"][0]["results"]
    assert len(results) == 0


def test_gdpr_agent_detects_pii_var():
    code = "ssn = input('enter ssn')\n"
    agent = GDPRAgent()
    sarif = agent.detect({"main.py": code})
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "GDPR-001"


def test_gdpr_agent_detects_missing_subject_id():
    code = """class Patient(db.Model):
    ssn = db.Column(db.String)
"""
    agent = GDPRAgent()
    sarif = agent.detect({"models.py": code})
    results = sarif["runs"][0]["results"]
    assert (
        len(results) == 2
    )  # One GDPR-001 (ssn assignment), one GDPR-002 (missing subject id)
    rule_ids = {r["ruleId"] for r in results}
    assert "GDPR-001" in rule_ids
    assert "GDPR-002" in rule_ids


def test_hipaa_agent_detects_phi_and_iam_wildcard():
    code = """# File handling patient medical_record
resource "aws_iam_policy" "wildcard" {
  policy = <<EOF
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
}
"""
    agent = HIPAAAgent()
    sarif = agent.detect({"policy.tf": code})
    results = sarif["runs"][0]["results"]
    assert len(results) >= 1
    assert results[0]["ruleId"] == "HIPAA-002"


def test_soc2_agent_detects_no_audit_log():
    code = """def write_data(user):
    db.session.add(user)
"""
    agent = SOC2Agent()
    sarif = agent.detect({"app.py": code})
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "SOC2-002"


def test_fedramp_agent_detects_insecure_cipher_and_tagging():
    code = """# Resource using insecure cipher
cipher = "3DES"
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}
"""
    agent = FedRAMPAgent()
    sarif = agent.detect({"infra.tf": code})
    results = sarif["runs"][0]["results"]
    rule_ids = {r["ruleId"] for r in results}
    assert "FEDRAMP-001" in rule_ids
    assert "FEDRAMP-002" in rule_ids


def test_org_policy_agent_custom_rules():
    with tempfile.TemporaryDirectory() as tmpdir:
        org_policy_data = {
            "id": "org-policy",
            "controls": [],
            "custom_rules": [
                {
                    "id": "ORG-RULE-999",
                    "pattern": r"\bTODO\b",
                    "message": "Production TODOs are forbidden",
                    "severity": "high",
                    "maps_to": ["SC-28"],
                }
            ],
        }
        with open(os.path.join(tmpdir, "org-policy.yaml"), "w") as fh:
            yaml.safe_dump(org_policy_data, fh)

        agent = OrgPolicyAgent(tmpdir)
        sarif = agent.detect({"code.py": "# TODO: fix this\n"})
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "ORG-RULE-999"
        assert results[0]["level"] == "error"


def test_nist_agent_wildcard_detection():
    agent = Nist80053Agent()

    # 1. Test requirements.txt with unpinned, wildcard, extras
    reqs_content = """
# comment
-r other.txt
requests[security]==2.3.*
flask[async]
numpy>=1.20
    """
    sarif_reqs = agent.detect({"requirements.txt": reqs_content})
    results_reqs = sarif_reqs["runs"][0]["results"]
    rule_ids_reqs = [r["ruleId"] for r in results_reqs]
    assert len(results_reqs) == 2
    assert all(rid == "NIST-800-53-001" for rid in rule_ids_reqs)
    messages_reqs = [r["message"]["text"] for r in results_reqs]
    assert any("requirements.txt wildcard version" in msg for msg in messages_reqs)
    assert any("requirements.txt unpinned dependency" in msg for msg in messages_reqs)

    # 2. Test package.json
    pkg_content = """{
      "dependencies": {
        "lodash": "*",
        "react": "^17.x",
        "vue": "latest",
        "express": "^4.17.1",
        "gitdep": "git+https://github.com/expressjs/express.git",
        "localpath": "file:../extra-libs"
      }
    }"""
    sarif_pkg = agent.detect({"package.json": pkg_content})
    results_pkg = sarif_pkg["runs"][0]["results"]
    assert len(results_pkg) == 3
    for r in results_pkg:
        assert r["ruleId"] == "NIST-800-53-001"
        assert "package.json wildcard version" in r["message"]["text"]

    # 3. Test Cargo.toml
    cargo_content = """
[package]
name = "test"

[dependencies]
rand = "*"
serde = "1.0.*"
tokio = "1.0.0"
    """
    sarif_cargo = agent.detect({"Cargo.toml": cargo_content})
    results_cargo = sarif_cargo["runs"][0]["results"]
    assert len(results_cargo) == 2
    for r in results_cargo:
        assert r["ruleId"] == "NIST-800-53-001"
        assert "Cargo.toml wildcard version" in r["message"]["text"]

    # 4. Test pyproject.toml PEP 621 collision and optional dependencies
    pyproject_content = """
[project]
name = "flask-app"
dependencies = [
    "flask[async]",
    "django>=4.*"
]

[project.optional-dependencies]
dev = [
    "pytest"
]
    """
    sarif_pyproject = agent.detect({"pyproject.toml": pyproject_content})
    results_pyproject = sarif_pyproject["runs"][0]["results"]
    assert len(results_pyproject) == 3

    # Verify line numbers are accurate (no flask-app collision)
    flask_finding = [
        r
        for r in results_pyproject
        if "flask[async]"
        in r["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
    ][0]
    django_finding = [
        r
        for r in results_pyproject
        if "django>=4.*"
        in r["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
    ][0]
    pytest_finding = [
        r
        for r in results_pyproject
        if "pytest"
        in r["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
    ][0]

    assert flask_finding["locations"][0]["physicalLocation"]["region"]["startLine"] == 5
    assert (
        django_finding["locations"][0]["physicalLocation"]["region"]["startLine"] == 6
    )
    assert (
        pytest_finding["locations"][0]["physicalLocation"]["region"]["startLine"] == 11
    )

    for r in results_pyproject:
        assert r["ruleId"] == "NIST-800-53-001"

    # 5. Test pyproject.toml Poetry groups and dev-dependencies
    poetry_content = """
[tool.poetry.dependencies]
python = "^3.9"

[tool.poetry.group.dev.dependencies]
black = "*"

[tool.poetry.dev-dependencies]
ruff = "*"
    """
    sarif_poetry = agent.detect({"pyproject.toml": poetry_content})
    results_poetry = sarif_poetry["runs"][0]["results"]
    assert len(results_poetry) == 2
    rule_ids_poetry = [r["ruleId"] for r in results_poetry]
    assert all(rid == "NIST-800-53-001" for rid in rule_ids_poetry)
    snippets = [
        r["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
        for r in results_poetry
    ]
    assert any("black = " in s for s in snippets)
    assert any("ruff = " in s for s in snippets)


def test_build_agents_includes_nist_agent():
    agents = build_agents(["nist-800-53"], "/app/packs")
    frameworks = {a.framework for a in agents}
    assert "nist-800-53" in frameworks
    assert any(isinstance(a, Nist80053Agent) for a in agents)
