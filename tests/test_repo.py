"""Structural checks: frontmatter, manifests, README coverage, license, changelog, line endings."""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO_NAME = "ship-check-skill"
PREFIX = "shipcheck-"
TEXT_SUFFIXES = {".md", ".py", ".json", ".yml", ".yaml", ".js", ".txt"}
TEXT_NAMES = {"LICENSE", ".gitignore", ".gitattributes", "Dockerfile", ".env.example"}
SKILLS = ["shipcheck-ci", "shipcheck-docker", "shipcheck-env", "shipcheck-preflight", "shipcheck-secrets"]
AGENTS = ["release-gatekeeper", "secret-rotation-guide"]


def frontmatter(path: Path) -> dict:
    """Parse simple YAML frontmatter by hand: `key: value` and folded (>-) blocks."""
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---", 4)
    if end == -1:
        return {}
    data, key = {}, None
    for line in text[4:end].split("\n"):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if m and not line.startswith((" ", "\t")):
            key, value = m.group(1), m.group(2).strip()
            data[key] = "" if value in {">-", ">", "|", "|-"} else value.strip('"').strip("'")
        elif key is not None:
            data[key] = (data[key] + " " + line.strip()).strip()
    return data


def skill_dirs():
    return sorted(p for p in (ROOT / "skills").iterdir() if p.is_dir() and not p.name.startswith("_"))


def agent_files():
    return sorted((ROOT / "agents").glob("*.md"))


def plugin_json() -> dict:
    return json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))


def line_count(path: Path) -> int:
    return path.read_text(encoding="utf-8").count("\n") + 1


class SkillTests(unittest.TestCase):
    def test_five_skills(self):
        self.assertEqual([p.name for p in skill_dirs()], SKILLS)

    def test_skill_frontmatter(self):
        for d in skill_dirs():
            with self.subTest(skill=d.name):
                fm = frontmatter(d / "SKILL.md")
                self.assertEqual(fm.get("name"), d.name)
                self.assertTrue(d.name.startswith(PREFIX))
                self.assertRegex(d.name, r"^[a-z0-9]+(-[a-z0-9]+)*$")
                self.assertTrue(fm.get("description"))
                self.assertLess(len(fm["description"]), 1024)
                self.assertIn("Use when", fm["description"])
                self.assertGreaterEqual(fm["description"].count('"'), 10, "5+ quoted trigger phrases")

    def test_skill_body(self):
        for d in skill_dirs():
            with self.subTest(skill=d.name):
                text = (d / "SKILL.md").read_text(encoding="utf-8")
                self.assertTrue(60 <= line_count(d / "SKILL.md") <= 200, f"{d.name}: {line_count(d / 'SKILL.md')} lines")
                for heading in ("## Inputs", "## Outputs", "## Steps", "## Decision rules", "## What NOT to do"):
                    self.assertIn(heading, text)
                self.assertIn("on Windows use `python`", text)
                self.assertRegex(text, r"authoriz|permission", "responsible-use rule")

    def test_referenced_scripts_exist(self):
        for d in skill_dirs():
            text = (d / "SKILL.md").read_text(encoding="utf-8")
            for rel in re.findall(r"\$\{CLAUDE_SKILL_DIR\}/([\w./-]+\.py)", text):
                with self.subTest(skill=d.name, script=rel):
                    self.assertTrue((d / rel).resolve().exists(), rel)

    def test_each_skill_with_a_script_references_it(self):
        expected = {"shipcheck-secrets": "secrets_scan.py", "shipcheck-env": "env_audit.py",
                    "shipcheck-docker": "dockerfile_lint.py", "shipcheck-ci": "ci_audit.py",
                    "shipcheck-preflight": "preflight.py"}
        for name, script in expected.items():
            with self.subTest(skill=name):
                self.assertTrue((ROOT / "skills" / name / script).exists())
                self.assertIn("${CLAUDE_SKILL_DIR}/" + script, (ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8"))

    def test_every_script_has_tests(self):
        scripts = sorted(ROOT.glob("skills/*/*.py")) + [ROOT / "examples" / "regenerate.py"]
        self.assertEqual(len(scripts), 6)
        for script in scripts:
            with self.subTest(script=script.name):
                name = "test_examples.py" if script.name == "regenerate.py" else f"test_{script.stem}.py"
                self.assertTrue((ROOT / "tests" / name).exists(), name)
                text = script.read_text(encoding="utf-8")
                self.assertIn("argparse", text)
                self.assertNotRegex(text, r"(?m)^\s*match .*:\s*$", "no match statements (Python 3.9)")
                self.assertIn("from __future__ import annotations", text)
                self.assertNotIn("newline=", text.replace('newline="\\n"', ""), "no Path.write_text(newline=...)")
                imports = set(re.findall(r"^(?:from|import) ([\w.]+)", text, re.M))
                self.assertFalse(imports & {"requests", "yaml", "httpx", "aiohttp", "tomllib", "toml"}, imports)

    def test_secrets_skill_puts_rotation_first(self):
        text = (ROOT / "skills" / "shipcheck-secrets" / "SKILL.md").read_text(encoding="utf-8")
        self.assertLess(text.index("Rotate first"), text.index("History cleanup"))
        self.assertIn("Do not print, quote, paste or log a secret value", text)

    def test_preflight_refuses_ship_it_with_open_blockers(self):
        text = (ROOT / "skills" / "shipcheck-preflight" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("refuses to say \"ship it\" while any high-severity", text)
        self.assertIn("Do not say \"ship it\"", text)


class AgentTests(unittest.TestCase):
    def test_two_agents(self):
        self.assertEqual([f.stem for f in agent_files()], AGENTS)

    def test_agent_frontmatter_and_body(self):
        for f in agent_files():
            with self.subTest(agent=f.name):
                fm = frontmatter(f)
                self.assertEqual(fm.get("name"), f.stem)
                self.assertTrue(fm.get("description"))
                tools = {t.strip() for t in fm.get("tools", "").split(",")}
                self.assertEqual(tools, {"Read", "Grep", "Glob", "Bash"}, "agents are read-only")
                self.assertTrue(40 <= line_count(f) <= 120, f"{f.name}: {line_count(f)} lines")
                text = f.read_text(encoding="utf-8")
                for heading in ("## How you work", "## Output format", "## Hard rules"):
                    self.assertIn(heading, text)


class ManifestTests(unittest.TestCase):
    def test_plugin_json(self):
        data = plugin_json()
        self.assertEqual(data["name"], REPO_NAME)
        self.assertEqual(data["version"], "1.0.0")
        self.assertEqual(data["license"], "MIT")
        self.assertEqual(data["author"]["name"], "Vivek Bhange")
        self.assertEqual(data["homepage"], f"https://github.com/vivekbhange-hub/{REPO_NAME}")
        self.assertEqual(data["repository"], f"https://github.com/vivekbhange-hub/{REPO_NAME}")
        self.assertTrue(6 <= len(data["keywords"]) <= 10)
        self.assertIn("claude-code", data["keywords"])
        self.assertIn("claude-skills", data["keywords"])

    def test_marketplace_json(self):
        data = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
        self.assertEqual(data["name"], REPO_NAME)
        self.assertEqual(data["owner"]["name"], "Vivek Bhange")
        self.assertEqual(len(data["plugins"]), 1)
        plugin = data["plugins"][0]
        self.assertEqual(plugin["name"], REPO_NAME)
        self.assertEqual(plugin["source"], "./")
        self.assertEqual(plugin["category"], "development")
        self.assertTrue(plugin["homepage"].endswith("/" + REPO_NAME))


class DocsTests(unittest.TestCase):
    def setUp(self):
        self.readme = (ROOT / "README.md").read_text(encoding="utf-8")

    def test_readme_mentions_every_skill_and_agent(self):
        for d in skill_dirs():
            self.assertIn(d.name, self.readme)
        for f in agent_files():
            self.assertIn(f.stem, self.readme)
        self.assertIn(f"/plugin marketplace add vivekbhange-hub/{REPO_NAME}", self.readme)
        self.assertIn(f"/plugin install {REPO_NAME}@{REPO_NAME}", self.readme)

    def test_readme_sections(self):
        for heading in ("## Try it in 60 seconds", "## How it works", "## Responsible use",
                        "## Principles and limits", "```mermaid", "examples/sample-app",
                        "examples/regenerate.py --materialize"):
            self.assertIn(heading, self.readme)

    def test_readme_excerpts_match_committed_outputs(self):
        """Every README line that quotes tool output must be a line of a committed output file."""
        outputs = set()
        for path in (ROOT / "examples" / "output").glob("*.md"):
            outputs.update(path.read_text(encoding="utf-8").split("\n"))
        pattern = re.compile(r"^(?:\S+(?::\d+)?  (?:SC|ED|DL|CI)\d{3}  .*|shipcheck (?:secrets|env|docker|ci): .*|"
                             r"Verdict: .*|\| (?:secrets|env|docker|ci) \| .*|\d+ findings \(.*|"
                             r"- \[(?:secrets|env|docker|ci)\] .*|    fix: .*)$")
        quoted = [line for line in self.readme.split("\n") if pattern.match(line)]
        self.assertGreaterEqual(len(quoted), 8, "the README should quote real output")
        for line in quoted:
            with self.subTest(line=line):
                self.assertIn(line, outputs)

    def test_readme_never_contains_a_secret_shaped_value(self):
        for needle in (r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{36}", r"sk_live_[0-9A-Za-z]{16}",
                       r"xox[abp]-[0-9A-Za-z-]{10}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"):
            self.assertNotRegex(self.readme, needle)

    def test_readme_local_links_exist(self):
        for target in re.findall(r"\]\(([^)#\s]+)\)", self.readme):
            if re.match(r"https?:", target):
                continue
            with self.subTest(target=target):
                self.assertTrue((ROOT / target).exists(), target)

    def test_license(self):
        text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("MIT", text)
        self.assertIn("Copyright (c) 2026 Vivek Bhange", text)

    def test_changelog_matches_version(self):
        version = plugin_json()["version"]
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"## [{version}] - ", changelog, "every released version needs a CHANGELOG entry")
        self.assertIn("## [1.0.0] - 2026-11-13", changelog)
        self.assertTrue((ROOT / "CONTRIBUTING.md").exists())

    def test_ci_and_gitattributes(self):
        self.assertIn("* text=auto eol=lf", (ROOT / ".gitattributes").read_text(encoding="utf-8"))
        ci = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
        for needle in ("ubuntu-latest", "windows-latest", "macos-latest", '"3.9"', '"3.12"', '"3.13"',
                       "actions/checkout@v4", "actions/setup-python@v5",
                       "python -m unittest discover -s tests -v"):
            self.assertIn(needle, ci)
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").split()
        for entry in (".DS_Store", "__pycache__/", "*.pyc", ".venv/", "*.tmp", ".shipcheck-demo/"):
            self.assertIn(entry, ignore)

    def test_text_files_use_lf(self):
        for path in ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts or ".shipcheck-demo" in path.parts:
                continue
            if path.suffix in TEXT_SUFFIXES or path.name in TEXT_NAMES:
                with self.subTest(file=str(path.relative_to(ROOT))):
                    self.assertNotIn(b"\r\n", path.read_bytes())

    def test_no_ai_attribution_anywhere(self):
        banned = ("Co-Authored-By", "Generated with", "Claude Sonnet", "noreply@anthropic.com")
        for path in ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts or path.name == "test_repo.py":
                continue
            if path.suffix in TEXT_SUFFIXES or path.name in TEXT_NAMES:
                text = path.read_text(encoding="utf-8")
                for phrase in banned:
                    with self.subTest(file=str(path.relative_to(ROOT)), phrase=phrase):
                        self.assertNotIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
