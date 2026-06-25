from __future__ import annotations
import ast
import re
import os
import yaml
from abc import ABC, abstractmethod


class DetectionAgent(ABC):
    framework: str

    @abstractmethod
    def detect(self, changed_files: dict[str, str]) -> dict:
        """Return a SARIF dict. engine tag: f'{self.framework}-agent'."""


class NoOpAgent(DetectionAgent):
    framework = "noop"

    def detect(self, changed_files: dict[str, str]) -> dict:
        return {"runs": []}


class DataFlowAgent(DetectionAgent):
    framework = "dataflow"

    def detect(self, changed_files: dict[str, str]) -> dict:
        results = []
        rules = [{"id": "DFA-001", "properties": {"confidence": "HIGH"}}]

        from audit_packs.dataflow import extract_data_flows

        for file_path, text in changed_files.items():
            lang = (
                "python"
                if file_path.endswith(".py")
                else "hcl"
                if file_path.endswith(".tf")
                else "yaml"
            )
            flows = extract_data_flows(text, lang)
            lines = text.splitlines()

            for flow in flows:
                if not flow.has_transform:
                    src_line_text = (
                        lines[flow.source_line - 1]
                        if 0 < flow.source_line <= len(lines)
                        else ""
                    )
                    sink_line_text = (
                        lines[flow.sink_line - 1]
                        if 0 < flow.sink_line <= len(lines)
                        else ""
                    )

                    results.append(
                        {
                            "ruleId": "DFA-001",
                            "level": "error",
                            "message": {
                                "text": f"Unprotected data flow from source {flow.source_type} (L{flow.source_line}) to sink {flow.sink_type} (L{flow.sink_line})"
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": file_path},
                                        "region": {
                                            "startLine": flow.sink_line,
                                            "snippet": {"text": sink_line_text.strip()},
                                        },
                                    }
                                }
                            ],
                            "codeFlows": [
                                {
                                    "threadFlows": [
                                        {
                                            "locations": [
                                                {
                                                    "location": {
                                                        "physicalLocation": {
                                                            "artifactLocation": {
                                                                "uri": file_path
                                                            },
                                                            "region": {
                                                                "startLine": flow.source_line,
                                                                "snippet": {
                                                                    "text": src_line_text.strip()
                                                                },
                                                            },
                                                        },
                                                        "message": {
                                                            "text": f"source: {flow.source_type}"
                                                        },
                                                    }
                                                },
                                                {
                                                    "location": {
                                                        "physicalLocation": {
                                                            "artifactLocation": {
                                                                "uri": file_path
                                                            },
                                                            "region": {
                                                                "startLine": flow.sink_line,
                                                                "snippet": {
                                                                    "text": sink_line_text.strip()
                                                                },
                                                            },
                                                        },
                                                        "message": {
                                                            "text": f"sink: {flow.sink_type}"
                                                        },
                                                    }
                                                },
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    )

        return {
            "runs": [
                {
                    "tool": {"driver": {"name": "dataflow-agent", "rules": rules}},
                    "results": results,
                }
            ]
        }


class GDPRAgent(DetectionAgent):
    framework = "gdpr"

    def detect(self, changed_files: dict[str, str]) -> dict:
        results = []
        rules = [
            {"id": "GDPR-001", "properties": {"confidence": "MEDIUM"}},
            {"id": "GDPR-002", "properties": {"confidence": "HIGH"}},
        ]

        pii_regex = re.compile(
            r"\b(ssn|dob|card_number|passport_no|social_security|date_of_birth|credit_card|cvv|tax_id)\b",
            re.IGNORECASE,
        )
        assign_regex = re.compile(r"^\s*([a-zA-Z_]\w*)\s*=")

        for file_path, text in changed_files.items():
            lines = text.splitlines()

            # GDPR-001: PII variable/field name patterns
            for i, line in enumerate(lines, start=1):
                m = assign_regex.match(line)
                if m:
                    var_name = m.group(1)
                    if pii_regex.search(var_name):
                        results.append(
                            {
                                "ruleId": "GDPR-001",
                                "level": "warning",
                                "message": {
                                    "text": f"Variable '{var_name}' matches a PII pattern. Ensure encryption at rest."
                                },
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": file_path},
                                            "region": {
                                                "startLine": i,
                                                "snippet": {"text": line.strip()},
                                            },
                                        }
                                    }
                                ],
                            }
                        )

            # GDPR-002: Missing data-subject-id in DB schemas
            if file_path.endswith(".py"):
                try:
                    tree = ast.parse(text)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.ClassDef):
                            is_model = (
                                any(
                                    "Model" in ast.unparse(base)
                                    or "Schema" in ast.unparse(base)
                                    for base in node.bases
                                )
                                or "Model" in node.name
                                or "Schema" in node.name
                            )

                            if is_model:
                                has_pii = False
                                has_subject_id = False
                                for body_item in node.body:
                                    if isinstance(body_item, ast.Assign):
                                        for target in body_item.targets:
                                            if isinstance(target, ast.Name):
                                                if pii_regex.search(target.id):
                                                    has_pii = True
                                                if target.id == "data_subject_id":
                                                    has_subject_id = True
                                if has_pii and not has_subject_id:
                                    results.append(
                                        {
                                            "ruleId": "GDPR-002",
                                            "level": "error",
                                            "message": {
                                                "text": f"Model/Schema class '{node.name}' contains PII fields but is missing a 'data_subject_id' field."
                                            },
                                            "locations": [
                                                {
                                                    "physicalLocation": {
                                                        "artifactLocation": {
                                                            "uri": file_path
                                                        },
                                                        "region": {
                                                            "startLine": node.lineno,
                                                            "snippet": {
                                                                "text": f"class {node.name}"
                                                            },
                                                        },
                                                    }
                                                }
                                            ],
                                        }
                                    )
                except Exception:
                    pass

        return {
            "runs": [
                {
                    "tool": {"driver": {"name": "gdpr-agent", "rules": rules}},
                    "results": results,
                }
            ]
        }


class HIPAAAgent(DetectionAgent):
    framework = "hipaa"

    def detect(self, changed_files: dict[str, str]) -> dict:
        results = []
        rules = [
            {"id": "HIPAA-001", "properties": {"confidence": "MEDIUM"}},
            {"id": "HIPAA-002", "properties": {"confidence": "HIGH"}},
        ]

        phi_regex = re.compile(
            r"\b(phi|patient_id|medical_record|mrn|health_plan|diagnosis|treatment_info)\b",
            re.IGNORECASE,
        )
        assign_regex = re.compile(r"^\s*([a-zA-Z_]\w*)\s*=")

        # HIPAA-002: IAM wildcards on patient-data resource paths
        wildcard_res = re.compile(
            r'"Resource"\s*:\s*"\*"\s*|\bresourced\b.*\*\b|resource\s+.*\*'
        )
        phi_context = re.compile(r"\b(phi|patient|health|medical)\b", re.IGNORECASE)

        for file_path, text in changed_files.items():
            lines = text.splitlines()
            has_phi_context = bool(phi_context.search(text))

            for i, line in enumerate(lines, start=1):
                # HIPAA-001: PHI field patterns
                m = assign_regex.match(line)
                if m:
                    var_name = m.group(1)
                    if phi_regex.search(var_name):
                        results.append(
                            {
                                "ruleId": "HIPAA-001",
                                "level": "warning",
                                "message": {
                                    "text": f"Variable '{var_name}' matches a PHI pattern. Ensure access controls and audit logging."
                                },
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": file_path},
                                            "region": {
                                                "startLine": i,
                                                "snippet": {"text": line.strip()},
                                            },
                                        }
                                    }
                                ],
                            }
                        )

                # HIPAA-002: IAM wildcards
                if has_phi_context and wildcard_res.search(line):
                    results.append(
                        {
                            "ruleId": "HIPAA-002",
                            "level": "error",
                            "message": {
                                "text": "IAM policy uses wildcard resource '*' in a file referencing PHI/patient-data."
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": file_path},
                                        "region": {
                                            "startLine": i,
                                            "snippet": {"text": line.strip()},
                                        },
                                    }
                                }
                            ],
                        }
                    )

        return {
            "runs": [
                {
                    "tool": {"driver": {"name": "hipaa-agent", "rules": rules}},
                    "results": results,
                }
            ]
        }


class SOC2Agent(DetectionAgent):
    framework = "soc2"

    def detect(self, changed_files: dict[str, str]) -> dict:
        results = []
        rules = [
            {"id": "SOC2-001", "properties": {"confidence": "HIGH"}},
            {"id": "SOC2-002", "properties": {"confidence": "MEDIUM"}},
        ]

        for file_path, text in changed_files.items():
            lines = text.splitlines()

            # SOC2-001: Missing change-approval
            is_deploy_file = any(
                file_path.endswith(ext) and name in file_path.lower()
                for ext in (".sh", ".py", ".json", ".txt")
                for name in ("release", "deploy", "config", "build")
            )
            if is_deploy_file:
                has_approval = any(
                    re.search(
                        r"(?i)(approve|sign-off|ticket|jira|pr-\d+|pull request)", line
                    )
                    for line in lines
                )
                if not has_approval:
                    results.append(
                        {
                            "ruleId": "SOC2-001",
                            "level": "error",
                            "message": {
                                "text": f"Deployment/config file '{file_path}' modified without change-approval metadata or references."
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": file_path},
                                        "region": {
                                            "startLine": 1,
                                            "snippet": {
                                                "text": lines[0] if lines else ""
                                            },
                                        },
                                    }
                                }
                            ],
                        }
                    )

            # SOC2-002: No audit log on write paths
            if file_path.endswith(".py"):
                try:
                    tree = ast.parse(text)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.FunctionDef):
                            has_write = False
                            has_log = False
                            for child in ast.walk(node):
                                if isinstance(child, ast.Call):
                                    func_str = (
                                        ast.unparse(child.func)
                                        if hasattr(ast, "unparse")
                                        else ""
                                    )
                                    if (
                                        "db.session.add" in func_str
                                        or func_str.endswith(".save")
                                    ):
                                        has_write = True
                                    if (
                                        "logging." in func_str
                                        or "logger." in func_str
                                        or "print" in func_str
                                    ):
                                        has_log = True
                            if has_write and not has_log:
                                results.append(
                                    {
                                        "ruleId": "SOC2-002",
                                        "level": "warning",
                                        "message": {
                                            "text": f"Function '{node.name}' has database writes but no logging or audit trails."
                                        },
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {
                                                        "uri": file_path
                                                    },
                                                    "region": {
                                                        "startLine": node.lineno,
                                                        "snippet": {
                                                            "text": f"def {node.name}"
                                                        },
                                                    },
                                                }
                                            }
                                        ],
                                    }
                                )
                except Exception:
                    pass

        return {
            "runs": [
                {
                    "tool": {"driver": {"name": "soc2-agent", "rules": rules}},
                    "results": results,
                }
            ]
        }


class FedRAMPAgent(DetectionAgent):
    framework = "fedramp"

    def detect(self, changed_files: dict[str, str]) -> dict:
        results = []
        rules = [
            {"id": "FEDRAMP-001", "properties": {"confidence": "HIGH"}},
            {"id": "FEDRAMP-002", "properties": {"confidence": "MEDIUM"}},
        ]

        insecure_cipher_regex = re.compile(
            r"(?i)(rc4|des|3des|md5|ssl_v3|tls_v1\b|tls_v1_1)", re.IGNORECASE
        )
        resource_def = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"')

        for file_path, text in changed_files.items():
            lines = text.splitlines()

            # FEDRAMP-001: FIPS-validated cipher list
            for i, line in enumerate(lines, start=1):
                if insecure_cipher_regex.search(line):
                    results.append(
                        {
                            "ruleId": "FEDRAMP-001",
                            "level": "error",
                            "message": {
                                "text": "Insecure cryptographic protocol or cipher detected (non-FIPS)."
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": file_path},
                                        "region": {
                                            "startLine": i,
                                            "snippet": {"text": line.strip()},
                                        },
                                    }
                                }
                            ],
                        }
                    )

            # FEDRAMP-002: IL4/IL5 resource tagging
            if file_path.endswith(".tf"):
                for i, line in enumerate(lines, start=1):
                    if resource_def.match(line):
                        has_tags = False
                        has_fedramp_tag = False
                        brace_count = 1
                        for j in range(i, min(i + 30, len(lines))):
                            next_line = lines[j]
                            if "{" in next_line:
                                brace_count += next_line.count("{")
                            if "}" in next_line:
                                brace_count -= next_line.count("}")
                                if brace_count <= 0:
                                    break
                            if "tags" in next_line:
                                has_tags = True
                            if any(
                                x in next_line.lower()
                                for x in ("fedramp", "impactlevel", "environment")
                            ):
                                has_fedramp_tag = True

                        if not (has_tags and has_fedramp_tag):
                            results.append(
                                {
                                    "ruleId": "FEDRAMP-002",
                                    "level": "warning",
                                    "message": {
                                        "text": "Resource is missing required FedRAMP environment/ImpactLevel tags."
                                    },
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {"uri": file_path},
                                                "region": {
                                                    "startLine": i,
                                                    "snippet": {"text": line.strip()},
                                                },
                                            }
                                        }
                                    ],
                                }
                            )

        return {
            "runs": [
                {
                    "tool": {"driver": {"name": "fedramp-agent", "rules": rules}},
                    "results": results,
                }
            ]
        }


class OrgPolicyAgent(DetectionAgent):
    framework = "org-policy"

    def __init__(self, packs_dir: str):
        self.packs_dir = packs_dir
        self.custom_rules = []
        try:
            org_policy_path = os.path.join(packs_dir, "org-policy.yaml")
            if os.path.exists(org_policy_path):
                with open(org_policy_path) as fh:
                    data = yaml.safe_load(fh) or {}
                self.custom_rules = data.get("custom_rules", [])
        except Exception as exc:
            import sys

            print(
                f"Warning: Failed to load custom rules in OrgPolicyAgent: {exc}",
                file=sys.stderr,
            )

    def detect(self, changed_files: dict[str, str]) -> dict:
        results = []
        rules = []

        for rule in self.custom_rules:
            rule_id = rule.get("id")
            if rule_id:
                rules.append({"id": rule_id, "properties": {"confidence": "HIGH"}})

        for file_path, text in changed_files.items():
            lines = text.splitlines()
            for rule in self.custom_rules:
                rule_id = rule.get("id")
                pattern_str = rule.get("pattern")
                msg = rule.get("message", "Custom policy rule violation")
                severity = rule.get("severity", "warning").lower()

                if not rule_id or not pattern_str:
                    continue

                try:
                    pat = re.compile(pattern_str)
                except Exception:
                    continue

                for i, line in enumerate(lines, start=1):
                    if pat.search(line):
                        results.append(
                            {
                                "ruleId": rule_id,
                                "level": "error"
                                if severity in ("high", "critical", "error")
                                else "warning",
                                "message": {"text": msg},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": file_path},
                                            "region": {
                                                "startLine": i,
                                                "snippet": {"text": line.strip()},
                                            },
                                        }
                                    }
                                ],
                            }
                        )

        return {
            "runs": [
                {
                    "tool": {"driver": {"name": "org-policy-agent", "rules": rules}},
                    "results": results,
                }
            ]
        }


def build_agents(frameworks: list[str], packs_dir: str) -> list[DetectionAgent]:
    agents: list[DetectionAgent] = [DataFlowAgent()]
    if "gdpr" in frameworks:
        agents.append(GDPRAgent())
    if "hipaa" in frameworks:
        agents.append(HIPAAAgent())
    if "soc2" in frameworks:
        agents.append(SOC2Agent())
    if "fedramp" in frameworks:
        agents.append(FedRAMPAgent())
    if "org-policy" in frameworks:
        agents.append(OrgPolicyAgent(packs_dir))
    return agents
