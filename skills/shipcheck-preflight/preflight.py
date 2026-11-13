#!/usr/bin/env python3
"""preflight: run the four shipcheck scripts and merge them into one go / no-go report.

Runs secrets_scan.py, env_audit.py, dockerfile_lint.py and ci_audit.py (each with --json) from
the sibling skill folders, then groups every finding into blockers (high), should-fix (medium)
and advisories (low and info). The verdict is computed, never written by hand:

  NO-GO             at least one high finding is open
  INCOMPLETE        a check failed to run, so nothing can be promised
  GO WITH CONDITIONS  no high findings, but medium findings remain
  GO                nothing at high or medium

"Ship it" appears only in the GO verdict. Exit code: 0 for GO and GO WITH CONDITIONS, 1 for
NO-GO, 2 for INCOMPLETE or bad usage. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKILLS = HERE.parent
CHECKS = [
    ("secrets", "shipcheck-secrets", "secrets_scan.py"),
    ("env", "shipcheck-env", "env_audit.py"),
    ("docker", "shipcheck-docker", "dockerfile_lint.py"),
    ("ci", "shipcheck-ci", "ci_audit.py"),
]
SEVERITIES = ("high", "medium", "low", "info")


def run_check(label: str, folder: str, script: str, root: Path, extra=()) -> dict:
    """Run one script with --json and return {"ok": bool, "data": dict | None, "error": str}."""
    command = [sys.executable, str(SKILLS / folder / script), str(root), "--json", "--fail-on", "never", *extra]
    try:
        done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "data": None, "error": f"could not run {script}: {exc}"}
    stdout = done.stdout.decode("utf-8", "replace")
    if done.returncode != 0:
        return {"ok": False, "data": None, "error": f"{script} exited {done.returncode}: "
                + done.stderr.decode("utf-8", "replace").strip()[:300]}
    try:
        return {"ok": True, "data": json.loads(stdout), "error": ""}
    except ValueError:
        return {"ok": False, "data": None, "error": f"{script} did not print JSON"}


def not_checked(label: str, data: dict) -> list:
    notes = []
    if label == "docker" and not data.get("dockerfiles"):
        notes.append("docker: no Dockerfile found")
    if label == "ci":
        if not data.get("workflows"):
            notes.append("ci: no GitHub Actions workflows found")
        for item in data.get("skipped", []):
            notes.append(f"ci: {item['file']} was NOT audited ({item['reason']})")
    if label == "env" and not data.get("sources", {}).get("code"):
        notes.append("env: no source file reads an environment variable")
    if label == "secrets" and not data.get("files_scanned"):
        notes.append("secrets: no files were scanned")
    return notes


def build_report(results: dict) -> dict:
    """Merge per-check results (label -> run_check output) into the report structure."""
    items = {s: [] for s in SEVERITIES}
    checks, notes, errors = {}, [], []
    for label, _folder, _script in CHECKS:
        result = results.get(label)
        if result is None:
            continue
        if not result["ok"]:
            errors.append(f"{label}: {result['error']}")
            checks[label] = {"status": "failed", "counts": {s: 0 for s in SEVERITIES}}
            continue
        data = result["data"]
        checks[label] = {"status": "ran", "counts": {s: 0 for s in SEVERITIES}}
        notes.extend(not_checked(label, data))
        for finding in data.get("findings", []):
            severity = finding.get("severity", "info")
            severity = severity if severity in items else "info"
            checks[label]["counts"][severity] += 1
            items[severity].append({
                "check": label, "file": finding.get("file", ""), "line": finding.get("line", 0),
                "rule": finding.get("rule", ""), "severity": severity,
                "message": finding.get("message", ""), "fix": finding.get("fix", "")})
    for group in items.values():
        group.sort(key=lambda f: (f["check"], f["file"], f["line"], f["rule"]))
    counts = {s: len(items[s]) for s in SEVERITIES}
    if counts["high"]:
        verdict = "NO-GO"
    elif errors:
        verdict = "INCOMPLETE"
    elif counts["medium"]:
        verdict = "GO WITH CONDITIONS"
    else:
        verdict = "GO"
    return {"tool": "preflight", "verdict": verdict, "counts": counts, "checks": checks,
            "blockers": items["high"], "should_fix": items["medium"],
            "advisories": items["low"] + items["info"], "not_checked": notes, "errors": errors}


def verdict_line(report: dict) -> str:
    c = report["counts"]
    verdict = report["verdict"]
    if verdict == "NO-GO":
        return (f"Verdict: NO-GO. {c['high']} blocker(s) are open; do not ship until each is fixed "
                "or explicitly accepted by the owner.")
    if verdict == "INCOMPLETE":
        return "Verdict: INCOMPLETE. A check did not run, so this report cannot clear a release."
    if verdict == "GO WITH CONDITIONS":
        return f"Verdict: GO WITH CONDITIONS. No blockers; {c['medium']} should-fix item(s) remain."
    return "Verdict: GO. Nothing at high or medium severity. Ship it."


def render_markdown(report: dict, max_per_section: int = 25) -> str:
    lines = ["# Pre-flight report", "", verdict_line(report), "", "| Check | High | Medium | Low | Info | Status |",
             "|---|---:|---:|---:|---:|---|"]
    for label, info in report["checks"].items():
        c = info["counts"]
        lines.append(f"| {label} | {c['high']} | {c['medium']} | {c['low']} | {c['info']} | {info['status']} |")

    def section(title, group, with_fix):
        lines.extend(["", f"## {title} ({len(group)})", ""])
        if not group:
            lines.append("None.")
            return
        for item in group[:max_per_section]:
            where = f"{item['file']}:{item['line']}" if item["line"] else item["file"]
            lines.append(f"- [{item['check']}] `{where}` {item['rule']}: {item['message']}")
            if with_fix and item["fix"]:
                lines.append(f"  - Fix: {item['fix']}")
        if len(group) > max_per_section:
            lines.append(f"- ... and {len(group) - max_per_section} more (run the script for the full list)")

    section("Blockers", report["blockers"], True)
    section("Should fix", report["should_fix"], True)
    section("Advisories", report["advisories"], False)
    lines.extend(["", "## Not checked", ""])
    lines.extend([f"- {n}" for n in report["not_checked"]] + [f"- {e}" for e in report["errors"]]
                 if (report["not_checked"] or report["errors"]) else ["Nothing was skipped."])
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="preflight.py",
        description="Run all four shipcheck scripts and print one go / no-go report.")
    parser.add_argument("path", nargs="?", default=".", help="project folder (default: .)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    parser.add_argument("--history", action="store_true", help="also scan recent git history for secrets")
    parser.add_argument("--fail-on", default="high", choices=["high", "medium", "never"],
                        help="exit 1 at this severity or above (default: high)")
    parser.add_argument("--max-per-section", type=int, default=25, help="cap listed items per section (default: 25)")
    args = parser.parse_args(argv)

    root = Path(args.path)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    results = {}
    for label, folder, script in CHECKS:
        extra = ["--history"] if args.history and label == "secrets" else []
        results[label] = run_check(label, folder, script, root, extra)
    report = build_report(results)
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else render_markdown(report, args.max_per_section))
    if report["verdict"] == "INCOMPLETE":
        return 2
    if report["verdict"] == "NO-GO":
        return 1
    if args.fail_on == "medium" and report["verdict"] == "GO WITH CONDITIONS":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
