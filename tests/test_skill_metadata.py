from pathlib import Path


def _frontmatter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), f"{path} is missing YAML frontmatter"
    end = text.find("\n---", 4)
    assert end != -1, f"{path} has unterminated YAML frontmatter"

    data = {}
    for line in text[4:end].splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data


def test_agent_skills_have_loader_required_descriptions():
    skill_files = sorted(Path(".agent/skills").glob("*/SKILL.md"))
    assert skill_files

    missing = [
        str(path) for path in skill_files if not _frontmatter(path).get("description")
    ]

    assert missing == []
