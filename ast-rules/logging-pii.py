import ast
import re

RULE_ID = "AST-003"
LANGUAGES = ["python"]
CONFIDENCE = "MEDIUM"
DESCRIPTION = "Logging call with object containing PII-named fields."

PII_REGEX = re.compile(
    r"(?i)(ssn|dob|card_number|passport_no|social_security|credit_card|cvv|tax_id)"
)


def _is_logging_call(node: ast.Call) -> bool:
    func_name = ast.unparse(node.func)
    return any(
        p in func_name
        for p in (
            "logging.info",
            "logging.warning",
            "logging.error",
            "logging.debug",
            "print",
            "logger.info",
            "logger.warning",
            "logger.error",
            "logger.debug",
        )
    )


def detect(tree: ast.AST, source_text: str, filename: str) -> list[dict]:
    results = []
    lines = source_text.splitlines()

    pii_classes = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            has_pii = False
            for body_item in node.body:
                if isinstance(body_item, ast.Assign):
                    for target in body_item.targets:
                        if isinstance(target, ast.Name) and PII_REGEX.search(target.id):
                            has_pii = True
            if has_pii:
                pii_classes.add(node.name)

    pii_vars = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Call):
                func_name = ast.unparse(node.value.func)
                if func_name in pii_classes:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            pii_vars.add(target.id)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    tname = target.id.lower()
                    if any(c.lower() in tname for c in pii_classes) or any(
                        p in tname for p in ("patient", "user", "customer")
                    ):
                        pii_vars.add(target.id)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_logging_call(node):
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in pii_vars:
                    line_no = node.lineno
                    snippet = (
                        lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
                    )
                    results.append(
                        {
                            "ruleId": RULE_ID,
                            "level": "warning",
                            "message": {
                                "text": f"Object '{arg.id}' containing sensitive PII fields is logged directly. Avoid logging raw data structures to prevent sensitive data leaks in logs."
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
