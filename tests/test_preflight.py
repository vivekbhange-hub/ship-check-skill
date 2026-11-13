"""Tests for skills/shipcheck-preflight/preflight.py."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from _load import load, write

pf = load("shipcheck-preflight", "preflight")


def finding(severity, rule="X1", file="a.py", line=1, message="m", fix="f"):
    return {"file": file, "line": line, "rule": rule, "name": "n", "severity": severity, "message": message, "fix": fix}


def ok(**data):
    data.setdefault("findings", [])
    return {"ok": True, "data": data, "error": ""}


def results(**kwargs):
    base = {"secrets": ok(files_scanned=3), "env": ok(sources={"code": ["a.py"]}),
            "docker": ok(dockerfiles=["Dockerfile"]), "ci": ok(workflows=["w.yml"], skipped=[])}
    base.update(kwargs)
    return base


class VerdictTests(unittest.TestCase):
    def test_clean_is_go_and_only_then_says_ship_it(self):
        report = pf.build_report(results())
        self.assertEqual(report["verdict"], "GO")
        self.assertIn("Ship it", pf.render_markdown(report))

    def test_any_high_is_no_go_and_never_says_ship_it(self):
        report = pf.build_report(results(docker=ok(dockerfiles=["D"], findings=[finding("high", "DL005")])))
        self.assertEqual(report["verdict"], "NO-GO")
        text = pf.render_markdown(report)
        self.assertNotIn("ship it", text.lower())
        self.assertIn("Verdict: NO-GO. 1 blocker(s)", text)

    def test_high_beats_a_failed_check(self):
        res = results(ci={"ok": False, "data": None, "error": "boom"},
                      secrets=ok(files_scanned=1, findings=[finding("high", "SC001")]))
        self.assertEqual(pf.build_report(res)["verdict"], "NO-GO")

    def test_failed_check_is_incomplete(self):
        report = pf.build_report(results(ci={"ok": False, "data": None, "error": "ci_audit.py exited 2: bad"}))
        self.assertEqual(report["verdict"], "INCOMPLETE")
        text = pf.render_markdown(report)
        self.assertNotIn("ship it", text.lower())
        self.assertIn("- ci: ci_audit.py exited 2: bad", text)
        self.assertIn("| ci | 0 | 0 | 0 | 0 | failed |", text)

    def test_medium_is_go_with_conditions(self):
        report = pf.build_report(results(env=ok(sources={"code": ["a"]}, findings=[finding("medium", "ED001")])))
        self.assertEqual(report["verdict"], "GO WITH CONDITIONS")
        self.assertNotIn("ship it", pf.render_markdown(report).lower())

    def test_low_and_info_are_advisories_only(self):
        report = pf.build_report(results(docker=ok(dockerfiles=["D"], findings=[finding("low"), finding("info")])))
        self.assertEqual(report["verdict"], "GO")
        self.assertEqual([f["severity"] for f in report["advisories"]], ["low", "info"])
        self.assertEqual(report["blockers"], [])

    def test_unknown_severity_is_treated_as_info(self):
        report = pf.build_report(results(env=ok(sources={"code": ["a"]}, findings=[finding("weird")])))
        self.assertEqual(report["counts"]["info"], 1)


class MergeTests(unittest.TestCase):
    def test_grouping_sorting_and_counts(self):
        report = pf.build_report(results(
            secrets=ok(files_scanned=1, findings=[finding("high", "SC001", "z.py", 3), finding("medium", "SC012", "a.py", 1)]),
            env=ok(sources={"code": ["a"]}, findings=[finding("high", "ED004", ".env.example", 2)]),
            docker=ok(dockerfiles=["D"], findings=[finding("medium", "DL001", "Dockerfile", 1)])))
        self.assertEqual([(f["check"], f["rule"]) for f in report["blockers"]], [("env", "ED004"), ("secrets", "SC001")])
        self.assertEqual([(f["check"], f["rule"]) for f in report["should_fix"]], [("docker", "DL001"), ("secrets", "SC012")])
        self.assertEqual(report["counts"], {"high": 2, "medium": 2, "low": 0, "info": 0})
        self.assertEqual(report["checks"]["secrets"]["counts"]["high"], 1)

    def test_not_checked_notes(self):
        report = pf.build_report({
            "secrets": ok(files_scanned=0), "env": ok(sources={"code": []}), "docker": ok(dockerfiles=[]),
            "ci": ok(workflows=["a.yml"], skipped=[{"file": "a.yml", "line": 3, "reason": "anchors, aliases and tags are not supported"}])})
        self.assertEqual(report["not_checked"], [
            "secrets: no files were scanned", "env: no source file reads an environment variable",
            "docker: no Dockerfile found", "ci: a.yml was NOT audited (anchors, aliases and tags are not supported)"])

    def test_markdown_layout_and_cap(self):
        many = [finding("high", "SC001", "f%02d.py" % i, i + 1, "msg%d" % i) for i in range(30)]
        text = pf.render_markdown(pf.build_report(results(secrets=ok(files_scanned=1, findings=many))), max_per_section=5)
        self.assertIn("## Blockers (30)", text)
        self.assertIn("- [secrets] `f00.py:1` SC001: msg0\n  - Fix: f", text)
        self.assertIn("... and 25 more", text)
        self.assertIn("## Should fix (0)\n\nNone.", text)
        self.assertIn("## Not checked\n\nNothing was skipped.", text)

    def test_fix_text_is_only_shown_for_blockers_and_should_fix(self):
        report = pf.build_report(results(docker=ok(dockerfiles=["D"], findings=[finding("low", fix="advisory-fix")])))
        self.assertNotIn("advisory-fix", pf.render_markdown(report))


class RunTests(unittest.TestCase):
    """End to end: the real scripts run as subprocesses against a temporary project."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = pf.main([str(a) for a in argv])
        return code, out.getvalue(), err.getvalue()

    def clean_project(self):
        write(self.root, "app.py", 'import os\nPORT = os.getenv("PORT", "8000")\n')
        write(self.root, ".env.example", "PORT=8000\n")
        write(self.root, ".gitignore", ".env\n")
        write(self.root, "Dockerfile", "FROM python:3.12-slim@sha256:" + "0" * 64 + "\nRUN useradd -m app\nUSER app\n"
                                       "HEALTHCHECK CMD true\nCMD [\"python\", \"app.py\"]\n")
        write(self.root, ".github/workflows/ci.yml",
              "on: push\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n"
              "      - uses: actions/checkout@" + "0123456789abcdef" * 2 + "01234567\n      - run: python -m unittest\n")

    def test_clean_project_is_go(self):
        self.clean_project()
        code, out, _ = self.run_cli(self.root)
        self.assertEqual(code, 0, out)
        self.assertIn("Verdict: GO. Nothing at high or medium severity. Ship it.", out)

    def test_a_leaked_key_blocks_the_release(self):
        self.clean_project()
        write(self.root, "settings.py", "KEY = '" + "AKIA" + "QX7M2KD9RT4VBN3H" + "'\n")
        code, out, _ = self.run_cli(self.root)
        self.assertEqual(code, 1)
        self.assertIn("Verdict: NO-GO", out)
        self.assertIn("[secrets] `settings.py:1` SC001: aws-access-key-id: AKIA****3H", out)
        self.assertNotIn("QX7M2KD9RT4VBN3H", out)
        self.assertNotIn("ship it", out.lower())

    def test_json_output_and_fail_on_medium(self):
        self.clean_project()
        write(self.root, "Dockerfile", "FROM python:3.12\nUSER app\nHEALTHCHECK CMD true\nCMD [\"x\"]\n")
        code, out, _ = self.run_cli(self.root, "--json")
        data = json.loads(out)
        self.assertEqual((code, data["verdict"]), (0, "GO"))
        write(self.root, "Dockerfile", "FROM python:latest\nUSER app\nHEALTHCHECK CMD true\nCMD [\"x\"]\n")
        code, out, _ = self.run_cli(self.root, "--json")
        self.assertEqual((code, json.loads(out)["verdict"]), (0, "GO WITH CONDITIONS"))
        self.assertEqual(self.run_cli(self.root, "--fail-on", "medium")[0], 1)

    def test_bad_path(self):
        code, _, err = self.run_cli(self.root / "missing")
        self.assertEqual(code, 2)
        self.assertIn("not a directory", err)

    def test_a_crashing_check_is_incomplete(self):
        calls = pf.CHECKS
        try:
            pf.CHECKS = [("secrets", "shipcheck-secrets", "does_not_exist.py")] + calls[1:]
            code, out, _ = self.run_cli(self.root)
        finally:
            pf.CHECKS = calls
        self.assertEqual(code, 2)
        self.assertIn("Verdict: INCOMPLETE", out)


if __name__ == "__main__":
    unittest.main()
