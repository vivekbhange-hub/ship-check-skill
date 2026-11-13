#!/usr/bin/env python3
"""env_audit: compare the environment variables your code reads with the ones you document.

Reads source files for env var reads (Python os.environ / os.getenv, Node process.env and
import.meta.env, Go os.Getenv, Ruby ENV, Java System.getenv, PHP getenv / $_ENV, Rust env::var)
and compares them with .env.example / .env.sample / .env.template, docker-compose `environment:`
and `env_file:`, and CI workflow `env:` blocks. It reports variables that are used but
undocumented, documented but unused, read without a fallback, duplicated keys and suspicious
names. A real `.env` is only ever reported by key name and whether the key is empty: values from
a real env file are never printed. Standard library only.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}
SEVERITIES = ("high", "medium", "low", "info")
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "venv", ".venv", "env", "__pycache__", ".tox", "dist", "build",
    "target", ".next", ".nuxt", "site-packages", ".idea", ".vscode", "coverage", ".mypy_cache",
}
LANG_BY_EXT = {
    ".py": "python", ".js": "node", ".jsx": "node", ".ts": "node", ".tsx": "node", ".mjs": "node",
    ".cjs": "node", ".vue": "node", ".svelte": "node", ".go": "go", ".rb": "ruby", ".rake": "ruby",
    ".java": "java", ".kt": "java", ".kts": "java", ".php": "php", ".rs": "rust",
}
COMMENT_PREFIX = {"python": ("#",), "node": ("//", "*", "/*"), "go": ("//",), "ruby": ("#",),
                  "java": ("//", "*", "/*"), "php": ("//", "#", "*", "/*"), "rust": ("//",)}
EXAMPLE_NAMES = {".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults",
                 "example.env", "sample.env", "env.example", "env.sample"}
EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")
SYSTEM_VARS = {"PATH", "HOME", "USER", "USERNAME", "PWD", "SHELL", "TERM", "LANG", "LC_ALL", "TMPDIR",
               "TEMP", "TMP", "HOSTNAME", "CI", "NODE_ENV", "LOGNAME", "TZ", "PYTHONPATH", "DISPLAY",
               "EDITOR", "OLDPWD", "SHLVL", "APPDATA", "LOCALAPPDATA", "USERPROFILE", "SYSTEMROOT"}
SYSTEM_PREFIXES = ("GITHUB_", "RUNNER_", "npm_", "KUBERNETES_", "BUILDKITE_", "CIRCLE_", "GITLAB_")
VITE_BUILTINS = {"MODE", "DEV", "PROD", "SSR", "BASE_URL"}
NAME = r"[A-Za-z_][A-Za-z0-9_]*"
SECRET_NAME = re.compile(
    r"(?i)(?<![A-Za-z])(?:secret|password|passwd|token|api_?key|secret_?key|private_?key|access_?key|"
    r"credentials?|auth_?key|signing_?key|encryption_?key)$")
PUBLIC_NAME = re.compile(r"(?i)(public|publishable)")
CLIENT_PREFIX = re.compile(r"^(?:VITE_|NEXT_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_|EXPO_PUBLIC_|GATSBY_)")
CLIENT_SECRET = re.compile(r"(?i)(secret|password|passwd|private_?key|service_?role|admin)")
PLACEHOLDER = re.compile(r"""(?ix)
    ^\s*$ | ^<[^>]*>$ | ^\$\{[^}]*\}$ | ^\$[A-Za-z_]\w*$ | ^\{\{.*\}\}$
  | changeme | change[-_\ ]?me | your[-_\ ] | <your | placeholder | redacted | dummy | example | sample
  | replace[-_\ ]?me | todo | fixme | insert[-_\ ] | x{4,} | \*{3,} | not[-_]?a[-_]?real | fake
  | ^(none|null|nil|true|false|secret|token|password|set[-_]?me|required|unset|empty|\.\.\.|-+)$
""")

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
    "ED001": ("used-undocumented", "medium", "Add the variable to .env.example with a safe placeholder and a comment."),
    "ED002": ("documented-unused", "low", "Remove it from the example file, or restore the code that reads it."),
    "ED003": ("duplicate-key", "medium", "Keep one definition; with dotenv the last one silently wins."),
    "ED004": ("secret-value-in-example", "high", "Replace the value with a placeholder such as changeme, and rotate it if it was real."),
    "ED005": ("secret-with-client-prefix", "high", "Variables with this prefix are bundled into browser code. Keep secrets server-side under an unprefixed name."),
    "ED006": ("real-env-missing-required", "medium", "Add the key to your real .env, or give the code a fallback."),
    "ED007": ("real-env-required-empty", "medium", "Set a value for the key in your real .env."),
    "ED008": ("real-env-undocumented", "low", "Add the key to .env.example so the next developer knows it exists."),
    "ED009": ("no-example-file", "medium", "Create .env.example (run with --suggest for a starting point)."),
}


def mask(value: str) -> str:
    value = value.strip()
    return value[:4] + "****" + value[-2:] if len(value) >= 12 else "****"


def is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER.search(value.strip().strip("'\"")))


def is_system(name: str) -> bool:
    return name in SYSTEM_VARS or name.startswith(SYSTEM_PREFIXES)


def is_example_file(name: str) -> bool:
    low = name.lower()
    return low in EXAMPLE_NAMES or (".env" in low and low.endswith(EXAMPLE_SUFFIXES))


def is_real_env(name: str) -> bool:
    low = name.lower()
    return (low == ".env" or low.startswith(".env.")) and not is_example_file(low)


def is_compose(name: str) -> bool:
    low = name.lower()
    return bool(re.match(r"^(docker-)?compose[\w.-]*\.ya?ml$", low))


# ---------------------------------------------------------------- reading code

def _fallback_after(tail: str, operators=(r"\|\|", r"\?\?", r"\?:")) -> bool:
    return bool(re.match(r"\s*(?:" + "|".join(operators) + ")", tail))


def _arg_default(tail: str) -> bool:
    """True when the call has a second argument that is not None/null/nil."""
    match = re.match(r"\s*,\s*([^)\n]*)", tail)
    return bool(match and match.group(1).strip() and not re.match(r"(None|null|nil|NULL)\b", match.group(1).strip()))


def _is_write(tail: str) -> bool:
    return bool(re.match(r"\s*(?:\|\||\?\?|&&)?=(?!=)", tail)) and not re.match(r"\s*=>", tail)


def _py(text):
    for m in re.finditer(r"(?<![\w.])(?:os\.)?environ\s*\[\s*(['\"])(" + NAME + r")\1\s*\]", text):
        if not _is_write(text[m.end():m.end() + 8]):
            yield m.start(), m.group(2), False, True
    for m in re.finditer(r"(?<![\w.])(?:os\.)?environ\.(get|setdefault)\(\s*(['\"])(" + NAME + r")\2", text):
        tail = text[m.end():m.end() + 200]
        yield m.start(), m.group(3), (m.group(1) == "setdefault") or _arg_default(tail), False
    for m in re.finditer(r"(?<![\w.])(?:os\.)?getenv\(\s*(['\"])(" + NAME + r")\1", text):
        yield m.start(), m.group(2), _arg_default(text[m.end():m.end() + 200]), False


def _node(text):
    for m in re.finditer(r"\b(?:process|Bun)\.env\.(" + NAME + r")", text):
        tail = text[m.end():m.end() + 80]
        if not _is_write(tail):
            yield m.start(), m.group(1), _fallback_after(tail.lstrip("!")), False
    for m in re.finditer(r"\b(?:process|Bun)\.env\[\s*(['\"`])(" + NAME + r")\1\s*\]", text):
        tail = text[m.end():m.end() + 80]
        if not _is_write(tail):
            yield m.start(), m.group(2), _fallback_after(tail), False
    for m in re.finditer(r"\bimport\.meta\.env\.(" + NAME + r")", text):
        if m.group(1) not in VITE_BUILTINS and not _is_write(text[m.end():m.end() + 8]):
            yield m.start(), m.group(1), _fallback_after(text[m.end():m.end() + 80]), False
    for m in re.finditer(r"\bimport\.meta\.env\[\s*(['\"])(" + NAME + r")\1\s*\]", text):
        yield m.start(), m.group(2), _fallback_after(text[m.end():m.end() + 80]), False
    for m in re.finditer(r"\bDeno\.env\.get\(\s*(['\"])(" + NAME + r")\1\s*\)", text):
        yield m.start(), m.group(2), _fallback_after(text[m.end():m.end() + 80]), False
    for m in re.finditer(r"\{([^{}]*)\}\s*=\s*(?:process|Bun)\.env\b", text):
        for part in m.group(1).split(","):
            item = re.match(r"\s*(" + NAME + r")\s*(?::\s*\w+\s*)?(=\s*\S.*)?$", part.strip(), re.S)
            if item:
                yield m.start(), item.group(1), bool(item.group(2)), False


def _go(text):
    for m in re.finditer(r"\bos\.Getenv\(\s*\"(" + NAME + r")\"\s*\)", text):
        yield m.start(), m.group(1), False, False
    for m in re.finditer(r"\bos\.LookupEnv\(\s*\"(" + NAME + r")\"\s*\)", text):
        yield m.start(), m.group(1), True, False


def _ruby(text):
    for m in re.finditer(r"\bENV\s*\[\s*(['\"])(" + NAME + r")\1\s*\]", text):
        tail = text[m.end():m.end() + 80]
        if not _is_write(tail):
            yield m.start(), m.group(2), _fallback_after(tail, (r"\|\|", r"\bor\b")), False
    for m in re.finditer(r"\bENV\.fetch\(\s*(['\"])(" + NAME + r")\1\s*(,|\))", text):
        tail = text[m.end():m.end() + 40]
        fallback = m.group(3) == "," or bool(re.match(r"\s*(?:\{|do\b)", tail))
        yield m.start(), m.group(2), fallback, not fallback
    for m in re.finditer(r"\bENV\.key\?\(\s*(['\"])(" + NAME + r")\1\s*\)", text):
        yield m.start(), m.group(2), True, False


def _java(text):
    for m in re.finditer(r"\bSystem\.getenv\(\s*\"(" + NAME + r")\"\s*\)", text):
        yield m.start(), m.group(1), _fallback_after(text[m.end():m.end() + 80], (r"\?:", r"\?\?")), False
    for m in re.finditer(r"\bgetenv\(\)\s*\.getOrDefault\(\s*\"(" + NAME + r")\"\s*,", text):
        yield m.start(), m.group(1), True, False
    for m in re.finditer(r"@Value\(\s*\"\$\{([A-Z_][A-Z0-9_]*)(:[^}]*)?\}\"", text):
        yield m.start(), m.group(1), bool(m.group(2)), False


def _php(text):
    for m in re.finditer(r"\bgetenv\(\s*(['\"])(" + NAME + r")\1\s*\)", text):
        yield m.start(), m.group(2), _fallback_after(text[m.end():m.end() + 80], (r"\?:", r"\?\?", r"\|\|")), False
    for m in re.finditer(r"\$_ENV\s*\[\s*(['\"])(" + NAME + r")\1\s*\]", text):
        tail = text[m.end():m.end() + 80]
        if not _is_write(tail):
            yield m.start(), m.group(2), _fallback_after(tail, (r"\?\?", r"\?:")), False
    for m in re.finditer(r"(?<![\w>:$])env\(\s*(['\"])(" + NAME + r")\1\s*(,[^)]*)?\)", text):
        default = (m.group(3) or "")[1:].strip()
        yield m.start(), m.group(2), bool(default) and default.lower() != "null", False


def _rust(text):
    for m in re.finditer(r"\benv::var\(\s*\"(" + NAME + r")\"\s*\)", text):
        tail = text[m.end():m.end() + 80]
        yield m.start(), m.group(1), bool(re.match(r"\s*\.(?:unwrap_or|unwrap_or_else|unwrap_or_default|ok)\b", tail)), False


READERS = {"python": _py, "node": _node, "go": _go, "ruby": _ruby, "java": _java, "php": _php, "rust": _rust}
DYNAMIC = {
    "python": r"(?<![\w.])(?:os\.)?environ\s*\[\s*(?!['\"])|(?<![\w.])(?:os\.)?(?:getenv|environ\.get)\(\s*(?!['\"])",
    "node": r"\b(?:process|Bun)\.env\[\s*(?!['\"`])",
    "go": r"\bos\.Getenv\(\s*(?!\")",
    "ruby": r"\bENV\s*\[\s*(?!['\"])",
    "java": r"\bSystem\.getenv\(\s*(?!\"|\))",
    "php": r"\bgetenv\(\s*(?!['\"])|\$_ENV\s*\[\s*(?!['\"])",
    "rust": r"\benv::var\(\s*(?!\")",
}


def read_source(rel: str, text: str, lang: str):
    """Return (reads, dynamic_count) for one source file. A read is (name, line, fallback, strict)."""
    reads = []
    prefixes = COMMENT_PREFIX[lang]
    seen = set()
    for pos, name, fallback, strict in READERS[lang](text):
        line_start = text.rfind("\n", 0, pos) + 1
        if text[line_start:pos].strip().startswith(prefixes):
            continue
        line = text.count("\n", 0, pos) + 1
        key = (name, line, pos)
        if key in seen:
            continue
        seen.add(key)
        reads.append((name, line, fallback, strict))
    dynamic = 0
    for m in re.finditer(DYNAMIC[lang], text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        if not text[line_start:m.start()].strip().startswith(prefixes):
            dynamic += 1
    return reads, dynamic


# ---------------------------------------------------------------- reading config files

DOTENV_LINE = re.compile(r"^\s*(?:export\s+)?(" + NAME + r")\s*=\s*(.*?)\s*$")
COMMENTED_KEY = re.compile(r"^\s*#\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$")


def clean_value(raw: str) -> str:
    raw = raw.strip()
    if raw[:1] in ("'", '"'):
        quote = raw[0]
        end = raw.find(quote, 1)
        return raw[1:end] if end > 0 else raw[1:]
    return re.split(r"\s+#", raw, maxsplit=1)[0].strip()


def parse_dotenv(text: str) -> list:
    """Return [(name, line, value, commented)] for a dotenv-style file."""
    rows = []
    for number, line in enumerate(text.split("\n"), 1):
        m = DOTENV_LINE.match(line)
        if m and not line.lstrip().startswith("#"):
            rows.append((m.group(1), number, clean_value(m.group(2)), False))
            continue
        m = COMMENTED_KEY.match(line)
        if m:
            rows.append((m.group(1), number, clean_value(m.group(2)), True))
    return rows


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def env_blocks(text: str, header: str):
    """Yield (name, line, value) for entries under every `<header>:` block (mapping or list form)."""
    lines = text.split("\n")
    for index, line in enumerate(lines):
        m = re.match(r"^(\s*)(?:-\s+)?" + header + r":\s*(.*?)\s*(?:#.*)?$", line)
        if not m:
            continue
        base = len(m.group(1))
        inline = m.group(2)
        if inline and not inline.startswith(("|", ">")):
            yield from _inline_entries(inline, index + 1, header)
            continue
        for offset in range(index + 1, len(lines)):
            row = lines[offset]
            if not row.strip() or row.lstrip().startswith("#"):
                continue
            if indent_of(row) <= base and not row.lstrip().startswith("- "):
                break
            if indent_of(row) < base:
                break
            body = row.strip()
            if body.startswith("- "):
                body = body[2:].strip().strip("'\"")
                m2 = re.match(r"^(" + NAME + r")(?:=(.*))?$", body)
                if m2:
                    yield m2.group(1), offset + 1, m2.group(2) or ""
                elif header == "env_file":
                    yield body, offset + 1, ""
                continue
            m2 = re.match(r"^(" + NAME + r")\s*:\s*(.*?)\s*$", body)
            if m2:
                yield m2.group(1), offset + 1, clean_value(m2.group(2))


def _inline_entries(inline: str, number: int, header: str):
    if header == "env_file":
        for item in re.split(r"[\[\],]", inline):
            item = item.strip().strip("'\"")
            if item:
                yield item, number, ""


def compose_vars(text: str) -> list:
    """Names referenced as ${NAME} or $NAME in a compose file, as (name, line)."""
    found = []
    for number, line in enumerate(text.split("\n"), 1):
        if line.lstrip().startswith("#"):
            continue
        for m in re.finditer(r"\$\{(" + NAME + r")(?::?[-?+][^}]*)?\}", line):
            found.append((m.group(1), number))
    return found


# ---------------------------------------------------------------- audit

def walk(root: Path, patterns: tuple = ()):
    globs = load_ignore(root) + list(patterns)
    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            rel = (Path(folder) / name).relative_to(root).as_posix()
            if not path_ignored(rel, globs):
                yield rel


def read_text(path: Path):
    try:
        if path.stat().st_size > 1_000_000:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8-sig", "replace").replace("\r\n", "\n")


def where(items: list) -> list:
    return [f"{i['file']}:{i['line']}" for i in items]


def audit(root: Path, include_system: bool = False, exclude: tuple = ()) -> dict:
    root = Path(root)
    uses, dynamic, examples, compose, ci, real = {}, 0, {}, {}, {}, {}
    source_files = []
    duplicates = []
    example_files, compose_files, ci_files = [], [], []
    for rel in walk(root, exclude):
        name = Path(rel).name
        parts = rel.split("/")
        lang = LANG_BY_EXT.get(Path(rel).suffix.lower())
        text = None
        if is_example_file(name):
            text = read_text(root / rel)
            if text is None:
                continue
            example_files.append(rel)
            first_seen = {}
            for key, number, value, commented in parse_dotenv(text):
                examples.setdefault(key, []).append({"file": rel, "line": number, "value": value, "commented": commented})
                if not commented:
                    if key in first_seen:
                        duplicates.append({"file": rel, "line": number, "name": key, "first": first_seen[key]})
                    first_seen.setdefault(key, number)
        elif is_real_env(name) and len(parts) == 1:
            text = read_text(root / rel) or ""
            entry = real.setdefault(rel, {"keys": [], "empty": []})
            first_seen = {}
            for key, number, value, commented in parse_dotenv(text):
                if commented:
                    continue
                if key in first_seen:
                    duplicates.append({"file": rel, "line": number, "name": key, "first": first_seen[key], "real": True})
                first_seen.setdefault(key, number)
                entry["keys"].append(key)
                if value == "":
                    entry["empty"].append(key)
            entry["keys"] = sorted(set(entry["keys"]))
            entry["empty"] = sorted(set(entry["empty"]))
        elif is_compose(name):
            text = read_text(root / rel)
            if text is None:
                continue
            compose_files.append(rel)
            for key, number, _value in env_blocks(text, "environment"):
                compose.setdefault(key, []).append({"file": rel, "line": number})
            for key, number in compose_vars(text):
                compose.setdefault(key, []).append({"file": rel, "line": number})
            for ref, number, _value in env_blocks(text, "env_file"):
                target = root / Path(rel).parent / ref
                referenced = read_text(target) if target.is_file() else None
                for key, _n, _v, commented in parse_dotenv(referenced or ""):
                    if not commented:  # names only: values of a real env file are never kept
                        compose.setdefault(key, []).append({"file": rel, "line": number})
        elif rel.startswith(".github/workflows/") and name.lower().endswith((".yml", ".yaml")):
            text = read_text(root / rel)
            if text is None:
                continue
            ci_files.append(rel)
            for key, number, _value in env_blocks(text, "env"):
                ci.setdefault(key, []).append({"file": rel, "line": number})
        if lang and text is None:
            text = read_text(root / rel)
            if text is None:
                continue
            reads, dyn = read_source(rel, text, lang)
            dynamic += dyn
            if reads or dyn:
                source_files.append(rel)
            for key, number, fallback, strict in reads:
                uses.setdefault(key, []).append(
                    {"file": rel, "line": number, "fallback": fallback, "strict": strict})
    if not include_system:
        uses = {k: v for k, v in uses.items() if not is_system(k)}
    return build_report(uses, dynamic, examples, compose, ci, real, duplicates, example_files,
                        compose_files, ci_files, source_files)


def build_report(uses, dynamic, examples, compose, ci, real, duplicates, example_files,
                 compose_files, ci_files, source_files) -> dict:
    findings = []

    def add(rule, file, line, message, name):
        rname, severity, fix = RULES[rule]
        findings.append({"file": file, "line": line, "rule": rule, "name": rname, "severity": severity,
                         "variable": name, "message": message, "fix": fix})

    variables = {}
    for name in sorted(set(uses) | set(examples) | set(compose) | set(ci)):
        reads = uses.get(name, [])
        required = bool(reads) and not any(r["fallback"] for r in reads)
        variables[name] = {
            "read_in": where(reads), "required": required, "has_fallback": bool(reads) and not required,
            "documented": name in examples, "in_compose": name in compose, "in_ci": name in ci,
        }
    if not example_files and uses:
        add("ED009", ".env.example", 0, "no .env.example, .env.sample or .env.template found", "")
    for name, reads in sorted(uses.items()):
        if examples and name not in examples:
            info = variables[name]
            provided = [label for label, flag in (("compose", info["in_compose"]), ("CI", info["in_ci"])) if flag]
            first = reads[0]
            detail = "required, no fallback" if info["required"] else "has a fallback"
            extra = f"; set in {' and '.join(provided)}" if provided else ""
            add("ED001", first["file"], first["line"],
                f"{name} is read but not in the example file ({detail}{extra})", name)
            if (info["has_fallback"] or provided):
                findings[-1]["severity"] = "low"
    for name, items in sorted(examples.items()):
        if name not in uses and name not in compose and name not in ci and not is_system(name):
            first = items[0]
            add("ED002", first["file"], first["line"], f"{name} is documented but no code reads it", name)
    for dup in duplicates:
        what = "real env file" if dup.get("real") else "example file"
        add("ED003", dup["file"], dup["line"], f"{dup['name']} is defined twice in this {what} (first on line {dup['first']})", dup["name"])
    for name, items in sorted(examples.items()):
        if not SECRET_NAME.search(name) or PUBLIC_NAME.search(name):
            continue
        for item in items:
            value = item["value"]
            if item["commented"] or len(value) < 6 or is_placeholder(value) or value.isdigit() or INTERPOLATED.search(value):
                continue
            add("ED004", item["file"], item["line"],
                f"{name} has a real-looking value in the example file: {mask(value)}", name)
            break
    flagged = set()
    for name in sorted(set(uses) | set(examples)):
        if CLIENT_PREFIX.match(name) and CLIENT_SECRET.search(CLIENT_PREFIX.sub("", name)) and name not in flagged:
            flagged.add(name)
            spot = (uses.get(name) or examples.get(name))[0]
            add("ED005", spot["file"], spot["line"], f"{name} will be exposed to browsers by its prefix", name)
    for rel, info in sorted(real.items()):
        if rel == ".env":
            for name, reads in sorted(uses.items()):
                if variables[name]["required"] and name not in info["keys"] and not variables[name]["in_compose"]:
                    add("ED006", rel, 0, f"{name} is required by {reads[0]['file']}:{reads[0]['line']} but is not set in {rel}", name)
        for name in info["empty"]:
            if name in variables and variables[name]["required"]:
                add("ED007", rel, 0, f"{name} is empty in {rel} but the code needs a value", name)
        if examples:
            for name in info["keys"]:
                if name not in examples:
                    add("ED008", rel, 0, f"{name} is set in {rel} but not in the example file", name)
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"], f["variable"]))
    counts = Counter(f["severity"] for f in findings)
    return {
        "tool": "env_audit",
        "sources": {"code": sorted(source_files), "examples": sorted(example_files),
                    "compose": sorted(compose_files), "ci": sorted(ci_files), "real_env": sorted(real)},
        "dynamic_reads": dynamic,
        "real_env": real,
        "variables": variables,
        "counts": {s: counts.get(s, 0) for s in SEVERITIES},
        "findings": findings,
    }


INTERPOLATED = re.compile(r"\$\{|\$\(|\{\{")


def suggest(report: dict, uses_detail: dict = None) -> str:
    lines = []
    for name, info in report["variables"].items():
        if info["documented"] or not info["read_in"]:
            continue
        kind = "required" if info["required"] else "optional, the code has a fallback"
        lines.append(f"# {name}: read in {info['read_in'][0]} ({kind})")
        lines.append(f"{name}={'changeme' if SECRET_NAME.search(name) else ''}")
    return "\n".join(lines)


def format_text(report: dict) -> str:
    src = report["sources"]
    head = (f"shipcheck env: {len(src['code'])} source files read {sum(1 for v in report['variables'].values() if v['read_in'])} "
            f"variables; examples: {', '.join(src['examples']) or 'none'}")
    extra = []
    if src["compose"]:
        extra.append("compose: " + ", ".join(src["compose"]))
    if src["ci"]:
        extra.append("ci: " + ", ".join(src["ci"]))
    if src["real_env"]:
        extra.append("real env files (names only): " + ", ".join(src["real_env"]))
    lines = [head + ("; " + "; ".join(extra) if extra else "")]
    c = report["counts"]
    lines.append(f"{len(report['findings'])} findings ({c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info)")
    for f in report["findings"]:
        where_ = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        lines.append(f"{where_}  {f['rule']}  {f['severity']:<6}  {f['message']}")
    if report["dynamic_reads"]:
        lines.append(f"note: {report['dynamic_reads']} dynamic env reads (variable name not a literal) cannot be audited")
    return "\n".join(lines)


def format_table(report: dict) -> str:
    rows = [("variable", "required", "documented", "compose", "ci", "read in")]
    for name, info in report["variables"].items():
        rows.append((name, "yes" if info["required"] else ("fallback" if info["has_fallback"] else "-"),
                     "yes" if info["documented"] else "no", "yes" if info["in_compose"] else "no",
                     "yes" if info["in_ci"] else "no", ", ".join(info["read_in"][:2]) or "-"))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    return "\n".join("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(r)).rstrip() for r in rows)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="env_audit.py",
        description="Compare env vars read by code with .env.example, docker-compose and CI. "
                    "Never prints values from a real .env.")
    parser.add_argument("path", nargs="?", default=".", help="project folder (default: .)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    parser.add_argument("--fail-on", default="high", choices=["high", "medium", "low", "info", "never"],
                        help="exit 1 when a finding at or above this severity exists (default: high)")
    parser.add_argument("--table", action="store_true", help="also print a variable-by-variable table")
    parser.add_argument("--suggest", action="store_true", help="print lines to add to .env.example and exit")
    parser.add_argument("--include-system", action="store_true", help="also report PATH, HOME, CI, NODE_ENV, GITHUB_* ...")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching GLOB (repeatable)")
    args = parser.parse_args(argv)

    root = Path(args.path)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    report = audit(root, args.include_system, tuple(args.exclude))
    if args.suggest:
        text = suggest(report)
        print(text if text else "# nothing to add: every variable the code reads is documented")
        return 0
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(format_text(report))
        if args.table:
            print()
            print(format_table(report))
    if args.fail_on != "never":
        limit = RANK[args.fail_on]
        if any(RANK[f["severity"]] >= limit for f in report["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
