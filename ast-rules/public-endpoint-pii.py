import ast
import re

RULE_ID = "AST-004"
LANGUAGES = ["python"]
CONFIDENCE = "MEDIUM"
DESCRIPTION = "Decorator-less public endpoint returning model with PII fields."

PII_REGEX = re.compile(
    r"(?i)(ssn|dob|card_number|passport_no|social_security|credit_card|cvv|tax_id)"
)
ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch"}
AUTH_DECORATORS = {
    "login_required",
    "authenticated",
    "requires_auth",
    "auth_required",
    "roles_accepted",
    "roles_required",
}


def _is_route(decorator: ast.AST) -> bool:
    dec_str = ast.unparse(decorator)
    return any(r in dec_str for r in ROUTE_DECORATORS)


def _is_auth(decorator: ast.AST) -> bool:
    dec_str = ast.unparse(decorator)
    return any(a in dec_str for a in AUTH_DECORATORS)


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

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            has_route = False
            has_auth = False
            for dec in node.decorator_list:
                if _is_route(dec):
                    has_route = True
                if _is_auth(dec):
                    has_auth = True

            if has_route and not has_auth:
                returns_pii = False
                pii_var = ""

                for child in ast.walk(node):
                    if isinstance(child, ast.Return) and child.value:
                        ret_str = ast.unparse(child.value)
                        if isinstance(child.value, ast.Call):
                            func_name = ast.unparse(child.value.func)
                            if func_name in pii_classes:
                                returns_pii = True
                                pii_var = func_name
                                break
                        if isinstance(child.value, ast.Dict):
                            for key in child.value.keys:
                                if (
                                    key
                                    and isinstance(key, ast.Constant)
                                    and isinstance(key.value, str)
                                ):
                                    if PII_REGEX.search(key.value):
                                        returns_pii = True
                                        pii_var = key.value
                                        break
                        if any(c in ret_str for c in pii_classes) or any(
                            p in ret_str.lower()
                            for p in ("patient", "user_profile", "ssn")
                        ):
                            returns_pii = True
                            pii_var = ret_str
                            break

                if returns_pii:
                    line_no = node.lineno
                    snippet = (
                        lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
                    )
                    results.append(
                        {
                            "ruleId": RULE_ID,
                            "level": "error",
                            "message": {
                                "text": f"Public endpoint '{node.name}' lacks authentication decorators but returns sensitive data '{pii_var}' containing PII."
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
