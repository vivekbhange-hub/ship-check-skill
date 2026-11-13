#!/usr/bin/env python3
"""secrets_scan: find secrets in the files you are about to push. Output is always masked.

Scans the working tree (`git ls-files` when the folder is a git repo, a directory walk
otherwise) for provider-format secrets (AWS, GitHub, Slack, Stripe, Google, private key blocks,
JWTs, database URLs with passwords), generic `password=` / `secret=` / `token=` assignments and
long high-entropy strings in assignments. `--history` also scans the added lines of the last N
commits. It also reports `.env`-style files that are tracked by git or missing from .gitignore.

A secret value is never printed: only the first 4 and last 2 characters (or nothing for short
values), the file and line, a rule id, a severity and a stable fingerprint. Allowlist with
`.shipcheck-ignore` (path globs, `fp:<fingerprint>`, `rule:<ID>:<glob>`) or an inline
`shipcheck:ignore` comment. Standard library only.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}
SEVERITIES = ("high", "medium", "low", "info")
IGNORE_FILE = ".shipcheck-ignore"
INLINE_IGNORE = "shipcheck:ignore"
MAX_FILE_BYTES = 1_000_000
LONG_LINE = 1000

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "venv", ".venv", "env", "__pycache__",
    ".tox", ".mypy_cache", ".pytest_cache", ".idea", ".vscode", "dist", "build", "target",
    ".next", ".nuxt", "bower_components", "third_party", "site-packages", ".gradle", "Pods",
}
LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "poetry.lock",
    "Pipfile.lock", "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock", "uv.lock",
    "mix.lock", "pubspec.lock", "bun.lockb", "flake.lock", "gradle.lockfile",
}
BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".avif", ".pdf", ".zip", ".gz",
    ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".class", ".so", ".dll", ".dylib",
    ".exe", ".o", ".a", ".pyc", ".pyd", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3",
    ".mp4", ".mov", ".avi", ".webm", ".wasm", ".sqlite", ".db", ".bin", ".map", ".psd",
}
# Files where `key = value` with no quotes is normal; in source code only quoted values count.
CONFIG_EXTS = {".env", ".ini", ".cfg", ".conf", ".properties", ".yml", ".yaml", ".toml", ".sh",
               ".bash", ".zsh", ".tfvars", ".txt", ".envrc", ".config", ".dockerfile"}
CONFIG_NAMES = {"dockerfile", ".npmrc", ".pypirc", ".netrc", ".env"}

# ---------------------------------------------------------------- placeholders

PLACEHOLDER = re.compile(r"""(?ix)
    ^\s*$
  | ^<[^>]*>$ | ^\$\{[^}]*\}$ | ^\$\(.*\)$ | ^\$[A-Za-z_][A-Za-z0-9_]*$ | ^\{\{.*\}\}$
  | ^\{[A-Za-z_][\w.]*\}$ | ^%\(.*\)s$ | ^%[A-Za-z_]+%$ | ^%s$ | ^\#\{.*\}$ | ^<%.*%>$
  | ^(x{3,}|\*{3,}|\.{3,}|-{3,}|_{3,}|0{6,}|\#{3,}|\?{3,})$
  | changeme | change[-_\ ]?me | your[-_\ ] | <your | placeholder | redacted | dummy | example
  | sample | replace[-_\ ]?me | todo | fixme | insert[-_\ ] | my[-_]?(secret|password|token|api)
  | put[-_]?your | x{4,} | \*{4,} | secret[-_]?goes | not[-_]?a[-_]?real | fake | foobar
  | ^(none|null|nil|undefined|true|false|password|passwd|pass|secret|token|default|admin|root|
      test|testing|1234|12345|123456|12345678|abc123|letmein|string|empty|unset|required|
      xxx|yyy|zzz|redacted|hidden|masked|bearer|basic)$
""")
CODE_REF = re.compile(
    r"^(?:os|process|env|config|settings|self|this|request|req|ctx|vault|secrets|ENV|System|"
    r"getenv|Environment|Config|args|params|input|cfg|conf|opts|options|props|window|"
    r"context|data|form|body|headers|credentials|creds|auth)\b[.\[(]")
INTERPOLATION = re.compile(r"\$\{|\{\{|%\(|#\{|<%|\$\(|\{[A-Za-z_]\w*\}")
DOCUMENTED = {
    "AKIA" + "IOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY",
    "SflKxwRJSMeKKF2QT4fwpMeJf36P" + "Ok6yJV_adQssw5c",
}
NON_SECRET_KEY = re.compile(
    r"(?i)(hash|checksum|sha\d*|md5|integrity|digest|uuid|guid|etag|commit|revision|nonce|"
    r"fingerprint|signature_algorithm|public|publishable|build|version|image|thumbnail|"
    r"avatar|filename|path|class|style|color|font|css|href|src|url|uri|link)")


def is_placeholder(value: str) -> bool:
    value = value.strip().strip("'\"`")
    return bool(PLACEHOLDER.search(value)) or value in DOCUMENTED or value.endswith("EXAMPLE")


def mask(value: str) -> str:
    """First 4 + **** + last 2 for values of 12+ chars, otherwise fully masked."""
    value = value.strip()
    return value[:4] + "****" + value[-2:] if len(value) >= 12 else "****"


def fingerprint(rule: str, secret: str) -> str:
    return hashlib.sha256((rule + "\0" + secret).encode("utf-8", "replace")).hexdigest()[:12]


def entropy(value: str) -> float:
    counts = Counter(value)
    total = len(value)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


# ---------------------------------------------------------------- rules

# (id, name, severity, regex, secret group, fix)
ROTATE = "Rotate or revoke it first, then load it from an environment variable or secret manager."
RULES = [
    ("SC001", "aws-access-key-id", "high",
     re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"), 1, ROTATE),
    ("SC002", "aws-secret-access-key", "high",
     re.compile(r"(?i)aws_?secret_?(?:access_?)?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
     1, ROTATE),
    ("SC003", "github-token", "high",
     re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"), 1, ROTATE),
    ("SC004", "slack-token", "high", re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})"), 1, ROTATE),
    ("SC005", "slack-webhook", "high",
     re.compile(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)"), 1,
     "Regenerate the webhook in Slack, then store the URL as a secret."),
    ("SC006", "stripe-live-secret-key", "high",
     re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{16,})\b"), 1, ROTATE),
    ("SC007", "stripe-test-secret-key", "low",
     re.compile(r"\b((?:sk|rk)_test_[0-9A-Za-z]{16,})\b"), 1,
     "Test keys cannot move money, but roll it and keep it out of the repo anyway."),
    ("SC008", "google-api-key", "medium", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), 1,
     "Restrict the key by referrer or API in Google Cloud, or rotate it if it is unrestricted."),
    ("SC010", "jwt", "medium",
     re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"), 1,
     "A JWT is a live credential until it expires; revoke the session or rotate the signing key."),
]
PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")
KEY_BODY = re.compile(r"^\s*(?:[A-Za-z0-9+/=]{16,}|Proc-Type:|DEK-Info:)")
DB_URL = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver)://"
    r"(?P<user>[^\s:/@'\"`<>]*):(?P<pw>[^\s@/'\"`<>]{3,})@(?P<host>[^\s/:'\"`<>?]+)")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal", "db", "postgres",
               "mysql", "redis", "mongo", "database"}
ASSIGN = re.compile(r"""(?ix)
    (?P<key>[A-Za-z0-9_.\-]*?(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|
        auth[_-]?key|private[_-]?key|client[_-]?secret|credentials?))
    ["']?\s*(?::=|[:=]|=>)\s*
    (?:(?P<q>["'])(?P<qval>[^"'\s]{6,})(?P=q)|(?P<bare>[^\s"'\#,;<>(){}\[\]]{6,}))""")
ENTROPY_ASSIGN = re.compile(
    r"""(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*(?::=|[:=]|=>)\s*["']?(?P<val>[A-Za-z0-9+/_=\-]{20,})(?![A-Za-z0-9+/_=\-])""")
WORDLIKE = re.compile(r"^[a-z]+(?:[-_.][a-z]+)*$")

RULE_INFO = {r[0]: (r[1], r[2], r[5]) for r in RULES}
RULE_INFO.update({
    "SC009": ("private-key-block", "high", "Treat the key as burned: generate a new pair, replace the public half everywhere."),
    "SC011": ("database-url-password", "high", "Change the database password, then read the URL from the environment."),
    "SC012": ("generic-secret-assignment", "medium", "If it is real, rotate it and read it from the environment; if not, add a placeholder or allowlist it."),
    "SC013": ("high-entropy-string", "medium", "If it is a credential, rotate it and move it out of the file; otherwise allowlist its fingerprint."),
    "SC020": ("env-file-tracked", "high", "Run `git rm --cached <file>`, add it to .gitignore, and rotate every value it holds."),
    "SC021": ("env-file-not-gitignored", "medium", "Add the file name to .gitignore before the first `git add .`."),
    "SC022": ("gitignore-missing-env", "low", "Add `.env` to .gitignore so a real env file is never committed by accident."),
})


def is_config_file(rel: str) -> bool:
    name = Path(rel).name.lower()
    return (Path(rel).suffix.lower() in CONFIG_EXTS or name in CONFIG_NAMES or name.startswith(".env")
            or name.startswith("dockerfile.") or name.endswith(".dockerfile"))


def make(rule: str, rel: str, line: int, secret: str, masked: str = "", commit: str = "") -> dict:
    name, severity, fix = RULE_INFO[rule]
    masked = masked or mask(secret)
    item = {"file": rel, "line": line, "rule": rule, "name": name, "severity": severity,
            "masked": masked, "fingerprint": fingerprint(rule, secret),
            "message": f"{name}: {masked}", "fix": fix}
    if commit:
        item["commit"] = commit
    return item


def scan_lines(rel: str, numbered, commit: str = "") -> list:
    """Scan (line_number, text) pairs of one file; return findings with masked values only."""
    findings = []
    lines = list(numbered)
    config = is_config_file(rel)
    for index, (number, text) in enumerate(lines):
        if INLINE_IGNORE in text:
            continue
        claimed = []

        def add(rule, secret, masked=""):
            if secret and not any(secret in c or c in secret for c in claimed):
                claimed.append(secret)
                findings.append(make(rule, rel, number, secret, masked, commit))

        for rule, _name, _sev, regex, group, _fix in RULES:
            for match in regex.finditer(text):
                secret = match.group(group)
                if not is_placeholder(secret):
                    add(rule, secret)
        if PRIVATE_KEY.search(text):
            following = [t for _n, t in lines[index + 1:index + 3]]
            if any(KEY_BODY.match(t) for t in following):
                add("SC009", PRIVATE_KEY.search(text).group(0), "[private key block]")
        for match in DB_URL.finditer(text):
            password = match.group("pw")
            if is_placeholder(password) or INTERPOLATION.search(password):
                continue
            local = match.group("host").lower() in LOCAL_HOSTS
            add("SC011", password)
            if local and findings and findings[-1]["rule"] == "SC011" and findings[-1]["line"] == number:
                findings[-1]["severity"] = "low"
                findings[-1]["message"] += " (local development host)"
        if len(text) > LONG_LINE:
            continue
        for match in ASSIGN.finditer(text):
            value = match.group("qval")
            quoted = value is not None
            value = value if quoted else match.group("bare")
            if not quoted and not config:
                continue
            key = match.group("key")
            if is_placeholder(value) or INTERPOLATION.search(value) or CODE_REF.match(value):
                continue
            if value.startswith(("$", "@", "%", "&", "*", "!", "/", "./", "../", "~", "http://", "https://")):
                continue
            if re.match(r"^[A-Za-z]:[\\/]", value):
                continue
            normalized = re.sub(r"[^a-z0-9]", "", value.lower())
            if normalized and normalized in re.sub(r"[^a-z0-9]", "", key.lower()):
                continue
            if quoted and not config and (WORDLIKE.match(value) or re.search(r"[()|\^]", value)):
                continue
            if re.search(r"(?i)(type|expires?|ttl|length|count|name|header|prefix|url|uri|path|id)$", key):
                continue
            add("SC012", value)
        for match in ENTROPY_ASSIGN.finditer(text):
            value, key = match.group("val"), match.group("key")
            if is_placeholder(value) or NON_SECRET_KEY.search(key) or INTERPOLATION.search(value):
                continue
            if not (re.search(r"[A-Za-z]", value) and re.search(r"\d", value)):
                continue
            if "/" in value and re.fullmatch(r"[a-z0-9_./-]+", value):
                continue
            hexish = re.fullmatch(r"[0-9a-fA-F]+", value) is not None
            if hexish and (len(value) < 32 or entropy(value) < 3.0):
                continue
            if not hexish and entropy(value) < 4.0:
                continue
            add("SC013", value)
    return findings


# ---------------------------------------------------------------- allowlist

class Allowlist:
    def __init__(self, text: str = ""):
        self.globs, self.fingerprints, self.rule_globs = [], set(), []
        for raw in text.replace("\r\n", "\n").split("\n"):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("fp:"):
                self.fingerprints.add(line[3:].strip().lower())
            elif re.fullmatch(r"[0-9a-f]{12}", line):
                self.fingerprints.add(line)
            elif line.startswith("rule:"):
                _, _, rest = line.partition(":")
                rule, _, glob = rest.partition(":")
                self.rule_globs.append((rule.strip().upper(), glob.strip() or "*"))
            else:
                self.globs.append(line)

    def path_ignored(self, rel: str) -> bool:
        name = Path(rel).name
        for glob in self.globs:
            if glob.endswith("/") and (rel + "/").startswith(glob.lstrip("/")):
                return True
            if fnmatch.fnmatch(rel, glob.lstrip("/")) or ("/" not in glob and fnmatch.fnmatch(name, glob)):
                return True
        return False

    def finding_ignored(self, finding: dict) -> bool:
        if finding["fingerprint"] in self.fingerprints:
            return True
        return any(finding["rule"] == rule and fnmatch.fnmatch(finding["file"], glob)
                   for rule, glob in self.rule_globs)


# ---------------------------------------------------------------- file discovery

def git(root: Path, *args):
    """Run git in `root`; return stdout text, or None when git is missing or the command fails."""
    try:
        done = subprocess.run(["git", "-C", str(root), "-c", "core.quotepath=off", *args],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.decode("utf-8", "replace") if done.returncode == 0 else None


def use_git(root: Path) -> bool:
    if git(root, "rev-parse", "--is-inside-work-tree") is None:
        return False
    # A folder that the enclosing repo ignores (for example a demo directory) is walked instead.
    try:
        ignored = subprocess.run(["git", "-C", str(root), "check-ignore", "-q", "--", str(root)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        return ignored.returncode != 0
    except (OSError, subprocess.SubprocessError):
        return False


def skip_path(rel: str) -> bool:
    parts = rel.split("/")
    name = parts[-1]
    if any(p in SKIP_DIRS for p in parts[:-1]):
        return True
    low = name.lower()
    return (name in LOCKFILES or low.endswith((".lock", ".min.js", ".min.css", ".map", ".lockb"))
            or Path(low).suffix in BINARY_EXTS or name == IGNORE_FILE)


def list_files(root: Path, git_mode: bool) -> list:
    if git_mode:
        out = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard") or ""
        names = sorted({n for n in out.split("\0") if n})
        return [n for n in names if (root / n).is_file() and not skip_path(n)]
    found = []
    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            rel = (Path(folder) / name).relative_to(root).as_posix()
            if not skip_path(rel):
                found.append(rel)
    return sorted(found)


def read_text(path: Path):
    """Return the decoded text, or None for binary, huge or unreadable files."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8-sig", "replace").replace("\r\n", "\n")


# ---------------------------------------------------------------- env file hygiene

ENV_EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults", ".schema")


def is_env_file(rel: str) -> bool:
    name = Path(rel).name.lower()
    if name.endswith(ENV_EXAMPLE_SUFFIXES) or name.startswith("example"):
        return False
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def gitignore_covers(root: Path, name: str) -> bool:
    path = root / ".gitignore"
    if not path.is_file():
        return False
    for raw in path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").split("\n"):
        pattern = raw.strip()
        if not pattern or pattern.startswith(("#", "!")):
            continue
        pattern = pattern.lstrip("/").rstrip("/")
        if pattern.startswith("**/"):
            pattern = pattern[3:]
        if fnmatch.fnmatch(name, pattern):
            return True
    return False


def env_hygiene(root: Path, git_mode: bool) -> list:
    findings = []
    tracked = set((git(root, "ls-files", "-z") or "").split("\0")) if git_mode else set()
    candidates = set()
    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in files:
            rel = (Path(folder) / name).relative_to(root).as_posix()
            if is_env_file(rel):
                candidates.add(rel)
    for rel in sorted(candidates):
        if rel in tracked:
            findings.append(make("SC020", rel, 0, rel, "[file]"))
            continue
        if git_mode:
            ignored = subprocess.run(["git", "-C", str(root), "check-ignore", "-q", "--", rel],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        else:
            ignored = gitignore_covers(root, Path(rel).name)
        if not ignored:
            findings.append(make("SC021", rel, 0, rel, "[file]"))
    has_example = any(Path(p).name.lower().startswith(".env.") and Path(p).name.lower().endswith(
        ENV_EXAMPLE_SUFFIXES) for p in _walk_names(root))
    if has_example and not any(f["rule"] in ("SC020", "SC021") for f in findings) \
            and not gitignore_covers(root, ".env") and ".env" not in candidates:
        findings.append(make("SC022", ".gitignore", 0, ".gitignore", "[file]"))
    return findings


def _walk_names(root: Path):
    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in files:
            yield (Path(folder) / name).relative_to(root).as_posix()


# ---------------------------------------------------------------- history

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def scan_history(root: Path, count: int, allow: Allowlist) -> list:
    out = git(root, "log", f"-n{count}", "-p", "-U0", "--no-color", "--no-ext-diff", "--no-renames",
              "--format=@@commit %H")
    if out is None:
        return []
    findings, seen = [], {}
    commit, path, number, buffer = "", None, 0, []

    def flush():
        nonlocal buffer
        if path and buffer and not skip_path(path) and not allow.path_ignored(path):
            for item in scan_lines(path, buffer, commit[:7]):
                key = (item["fingerprint"], item["file"])
                seen[key] = item  # newest first, so the last assignment is the oldest commit
        buffer = []

    for line in out.split("\n"):
        if line.startswith("@@commit "):
            flush()
            commit, path = line.split(" ", 1)[1].strip(), None
        elif line.startswith("+++ "):
            flush()
            path = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("@@"):
            flush()
            match = HUNK.match(line)
            number = int(match.group(1)) if match else 0
        elif line.startswith("+") and path:
            buffer.append((number, line[1:]))
            number += 1
    flush()
    findings = [f for f in seen.values() if not allow.finding_ignored(f)]
    return findings


# ---------------------------------------------------------------- scan

def scan(root: Path, history: int = 0, use_git_files: bool = True, allow: Allowlist = None) -> dict:
    root = Path(root)
    if root.is_file():
        files_root, only = root.parent, [root.name]
    else:
        files_root, only = root, None
    if allow is None:
        ignore_path = files_root / IGNORE_FILE
        allow = Allowlist(ignore_path.read_text(encoding="utf-8", errors="replace")
                          if ignore_path.is_file() else "")
    git_mode = use_git_files and use_git(files_root)
    files = only if only is not None else list_files(files_root, git_mode)
    findings, scanned, skipped = [], 0, 0
    for rel in files:
        if allow.path_ignored(rel):
            skipped += 1
            continue
        text = read_text(files_root / rel)
        if text is None:
            skipped += 1
            continue
        scanned += 1
        findings.extend(scan_lines(rel, enumerate(text.split("\n"), 1)))
    if only is None:
        findings.extend(f for f in env_hygiene(files_root, git_mode) if not allow.path_ignored(f["file"]))
    allowlisted = sum(1 for f in findings if allow.finding_ignored(f))
    findings = [f for f in findings if not allow.finding_ignored(f)]
    if history and git_mode:
        findings.extend(scan_history(files_root, history, allow))
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"], f.get("commit", "")))
    counts = Counter(f["severity"] for f in findings)
    return {"tool": "secrets_scan", "git": git_mode, "files_scanned": scanned, "files_skipped": skipped,
            "history_commits": history if history and git_mode else 0, "allowlisted": allowlisted,
            "counts": {s: counts.get(s, 0) for s in SEVERITIES}, "findings": findings}


def location(item: dict) -> str:
    where = f"{item['file']}:{item['line']}" if item["line"] else item["file"]
    return where + (f" @{item['commit']}" if item.get("commit") else "")


def format_text(result: dict) -> str:
    c = result["counts"]
    total = len(result["findings"])
    head = (f"shipcheck secrets: scanned {result['files_scanned']} files, {total} findings "
            f"({c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info)")
    lines = [head]
    for f in result["findings"]:
        lines.append(f"{location(f)}  {f['rule']}  {f['severity']:<6}  {f['name']}  {f['masked']}  fp:{f['fingerprint']}")
    if result["allowlisted"]:
        lines.append(f"allowlisted: {result['allowlisted']}")
    if any(f["severity"] in ("high", "medium") for f in result["findings"]):
        lines.append("Treat every secret above as exposed: rotate or revoke first, clean history later.")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="secrets_scan.py",
        description="Scan a folder (or git repo) for leaked secrets. Output is always masked.")
    parser.add_argument("path", nargs="?", default=".", help="folder or file to scan (default: .)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    parser.add_argument("--fail-on", default="high", choices=["high", "medium", "low", "info", "never"],
                        help="exit 1 when a finding at or above this severity remains (default: high)")
    parser.add_argument("--history", action="store_true", help="also scan added lines of recent commits")
    parser.add_argument("--history-commits", type=int, default=50, metavar="N",
                        help="how many commits --history looks back (default: 50)")
    parser.add_argument("--no-git", action="store_true", help="walk the folder instead of using git ls-files")
    parser.add_argument("--list-rules", action="store_true", help="print rule ids and exit")
    args = parser.parse_args(argv)

    if args.list_rules:
        for rule in sorted(RULE_INFO):
            name, severity, _fix = RULE_INFO[rule]
            print(f"{rule}  {severity:<6}  {name}")
        return 0
    target = Path(args.path)
    if not target.exists():
        print(f"error: {target} does not exist", file=sys.stderr)
        return 2
    if args.history_commits < 1:
        print("error: --history-commits must be at least 1", file=sys.stderr)
        return 2
    result = scan(target, args.history_commits if args.history else 0, not args.no_git)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(format_text(result))
    if args.fail_on != "never":
        limit = RANK[args.fail_on]
        if any(RANK[f["severity"]] >= limit for f in result["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
