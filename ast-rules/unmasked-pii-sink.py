import ast
import re

RULE_ID = "AST-001"
LANGUAGES = ["python"]
CONFIDENCE = "HIGH"
DESCRIPTION = "PII-named variable reaches a sink without masking."

PII_REGEX = re.compile(
    r"(?i)(ssn|dob|card_number|passport_no|social_security|credit_card|cvv|tax_id)"
)
MASKING_FUNCS = {"encrypt", "mask", "hash", "anonymise", "redact", "bcrypt"}


def _is_sink(node: ast.Call) -> bool:
    func_name = ast.unparse(node.func)
    if any(
        s in func_name
        for s in (
            "db.session.add",
            "requests.post",
            "requests.put",
            "logging.",
            "print",
        )
    ):
        return True
    if isinstance(node.func, ast.Attribute) and node.func.attr == "save":
        return True
    return False


def _has_masking(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func_name = ast.unparse(child.func).lower()
            if any(m in func_name for m in MASKING_FUNCS):
                return True
    return False


def detect(tree: ast.AST, source_text: str, filename: str) -> list[dict]:
    results = []
    lines = source_text.splitlines()

    pii_vars = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and PII_REGEX.search(target.id):
                    pii_vars[target.id] = node.lineno

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for arg in node.args.args:
                if PII_REGEX.search(arg.arg):
                    pii_vars[arg.arg] = node.lineno

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_sink(node):
            for arg in node.args:
                for child in ast.walk(arg):
                    if isinstance(child, ast.Name) and child.id in pii_vars:
                        if not _has_masking(arg):
                            line_no = node.lineno
                            snippet = (
                                lines[line_no - 1].strip()
                                if 0 < line_no <= len(lines)
                                else ""
                            )
                            results.append(
                                {
                                    "ruleId": RULE_ID,
                                    "level": "error",
                                    "message": {
                                        "text": f"PII variable '{child.id}' reaches sink '{ast.unparse(node.func)}' without masking/encryption."
                                    },
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {"uri": filename},
                                                "region": {
                                                    "startLine": line_no,
                                                    "snippet": {"text": snippet},
                                                },
                                            }
                                        }
                                    ],
                                }
                            )
    return results
