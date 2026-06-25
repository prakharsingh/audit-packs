import tempfile
import os
import yaml
from audit_packs.agents import (
    DetectionAgent,
    NoOpAgent,
    DataFlowAgent,
    GDPRAgent,
    HIPAAAgent,
    SOC2Agent,
    FedRAMPAgent,
    OrgPolicyAgent,
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
