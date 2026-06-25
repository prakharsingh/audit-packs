import ast
import re

RULE_ID = "AST-002"
LANGUAGES = ["python"]
CONFIDENCE = "HIGH"
DESCRIPTION = "DB query with user-controlled input, no parameterisation."

SQL_KEYWORDS = re.compile(r"(?i)\b(select|insert|update|delete|from|where)\b")
USER_INPUT_PATTERNS = re.compile(
    r"(?i)(request\.(args|form|json|values|data)|input\s*\()"
)


def _is_db_execute(node: ast.Call) -> bool:
    func_name = ast.unparse(node.func)
    return any(
        name in func_name
        for name in (
            "db.execute",
            "cursor.execute",
            "conn.execute",
            "connection.execute",
        )
    )


def _is_vulnerable_str(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        left_str = ast.unparse(node.left)
        if SQL_KEYWORDS.search(left_str):
            return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        caller_str = ast.unparse(node.func.value)
        if SQL_KEYWORDS.search(caller_str):
            return True
    return False


def detect(tree: ast.AST, source_text: str, filename: str) -> list[dict]:
    results = []
    lines = source_text.splitlines()

    user_vars = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            val_str = ast.unparse(node.value)
            if USER_INPUT_PATTERNS.search(val_str):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        user_vars.add(target.id)

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for arg in node.args.args:
                if "request" in arg.arg or "user_input" in arg.arg:
                    user_vars.add(arg.arg)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_db_execute(node):
            if node.args:
                first_arg = node.args[0]
                if _is_vulnerable_str(first_arg):
                    has_user_var = False
                    for child in ast.walk(first_arg):
                        if isinstance(child, ast.Name) and child.id in user_vars:
                            has_user_var = True
                            break
                        if isinstance(child, ast.Attribute):
                            attr_str = ast.unparse(child)
                            if USER_INPUT_PATTERNS.search(attr_str):
                                has_user_var = True
                                break
                    if has_user_var:
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
                                    "text": "Database query constructed using dynamic user input string interpolation. Use parameterized queries instead to prevent SQL injection."
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
