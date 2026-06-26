import re

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_unified_diff(diff_text: str) -> dict[str, set[int]]:
    result: dict[str, set[int]] = {}
    current: str | None = None
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current = line[len("+++ b/") :].strip()
            continue
        if line.startswith("+++ ") or line.startswith("--- "):
            continue
        m = _HUNK.match(line)
        if m and current is not None:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            if count > 0:
                result.setdefault(current, set()).update(range(start, start + count))
    return {f: lines for f, lines in result.items() if lines}
