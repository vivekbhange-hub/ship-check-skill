#!/usr/bin/env python3
"""dockerfile_lint: lint Dockerfiles for the footguns that hurt in production.

Understands multi-stage builds (layer rules only apply to stages that ship), line
continuations, heredocs and ARG/ENV scoping (global ARGs are expanded in FROM lines). Rule ids
DL001.. each carry a severity and a fix. Checks the .dockerignore next to the Dockerfile too.
Standard library only; never executes Docker.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shlex
import sys
from collections import Counter
from pathlib import Path

RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}
SEVERITIES = ("high", "medium", "low", "info")
SKIP_DIRS = {".git", "node_modules", "vendor", "venv", ".venv", "__pycache__", "dist", "build", "target"}

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
    "DL001": ("base-image-not-pinned", "medium", "Pin a specific version tag, for example node:20.11-alpine3.19."),
    "DL002": ("base-image-no-digest", "info", "For reproducible builds pin image@sha256:<digest> and let a bot bump it."),
    "DL003": ("runs-as-root", "medium", "Create a user and add `USER app` (or a numeric uid) before CMD in the final stage."),
    "DL004": ("add-instead-of-copy", "low", "Use COPY for local files; for URLs use curl with a checksum, or ADD --checksum."),
    "DL005": ("pipe-to-shell", "high", "Download to a file, verify its checksum or signature, then run it."),
    "DL006": ("apt-recommends", "low", "Add --no-install-recommends to apt-get install."),
    "DL007": ("apt-lists-not-cleaned", "low", "End the same RUN with `rm -rf /var/lib/apt/lists/*`."),
    "DL008": ("apt-update-own-layer", "medium", "Run `apt-get update && apt-get install ...` in a single RUN so the cache cannot go stale."),
    "DL009": ("copy-all-before-install", "low", "COPY only the manifest (package.json, requirements.txt, go.mod) and install first, then COPY the rest."),
    "DL010": ("secret-in-env-or-arg", "high", "Never bake secrets into the image: use `RUN --mount=type=secret` for build time and runtime environment variables for run time."),
    "DL011": ("no-healthcheck", "info", "Add a HEALTHCHECK, or rely on the orchestrator's probes and say so."),
    "DL012": ("expose-ssh", "medium", "Do not run sshd in a container; use `docker exec` or the platform's shell access."),
    "DL013": ("no-dockerignore", "medium", "Add a .dockerignore next to the Dockerfile so the build context stays small and clean."),
    "DL014": ("dockerignore-incomplete", "low", "Add the missing entries to .dockerignore."),
    "DL015": ("sudo", "low", "Remove sudo; build steps already run as root, and the final user should not need it."),
    "DL016": ("chmod-777", "medium", "Grant the narrowest mode that works, for example 755 for directories or 644 for files, or chown to the runtime user."),
    "DL017": ("pip-cache", "low", "Add --no-cache-dir, or set ENV PIP_NO_CACHE_DIR=1."),
    "DL018": ("install-without-lock", "low", "Install from a lockfile: `npm ci`, `yarn install --frozen-lockfile`, `pip install -r requirements.txt` with pinned versions."),
    "DL019": ("shell-form-cmd", "low", "Use exec form, for example CMD [\"node\", \"server.js\"], so signals reach your process."),
    "DL020": ("copies-secret-file", "high", "Remove the file from the image: add it to .dockerignore and pass secrets at run time."),
}

SECRET_ENV = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|credential|auth[_-]?key)")
NOT_SECRET = re.compile(r"(?i)(public|path|file|_url$|_uri$|_name$|_host$|_port$|_id$|_user$|_dir$|_ttl$|_expiry$)")
PLACEHOLDER = re.compile(r"""(?ix)^\s*$ | changeme | change[-_]?me | placeholder | your[-_] | <[^>]*> | x{4,}
    | example | dummy | replace[-_]?me | ^(none|null|false|true|secret|password|token)$""")
VALUE_PATTERNS = [re.compile(p) for p in (
    r"\bAKIA[0-9A-Z]{16}\b", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b",
    r"\bxox[abprs]-[A-Za-z0-9-]{10,}")]
SECRET_FILE = re.compile(
    r"(?i)(?:^|/)(?:\.env(?:\.(?!example|sample|template|dist)[\w.-]+)?|id_rsa|id_ed25519|id_ecdsa|"
    r"[\w.-]+\.pem|[\w.-]+\.p12|[\w.-]+\.pfx|\.npmrc|\.pypirc|\.netrc|\.aws|\.ssh)/?$")
INSTALL_CMD = re.compile(
    r"\b(?:npm\s+(?:ci|install|i)\b|yarn\s+install\b|yarn\s*(?:$|&&|;)|pnpm\s+(?:install|i)\b|pip3?\s+install\b|"
    r"python3?\s+-m\s+pip\s+install\b|poetry\s+install\b|pipenv\s+install\b|bundle\s+install\b|"
    r"composer\s+install\b|go\s+mod\s+download\b|cargo\s+fetch\b|dotnet\s+restore\b|uv\s+(?:sync|pip)\b)")
PIPE_SHELL = re.compile(
    r"(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+\S+=\S+\s+)?"
    r"(?:bash|sh|zsh|ash|dash|python[\d.]*|perl|ruby|node)\b"
    r"|\b(?:bash|sh)\s+(?:-c\s+)?[\"']?\$\(\s*(?:curl|wget)\b|<\(\s*(?:curl|wget)\b")
ARCHIVE = re.compile(r"(?i)\.(?:tar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz|tar\.zst)$")


class Instruction:
    __slots__ = ("keyword", "args", "line", "body", "stage")

    def __init__(self, keyword, args, line, body="", stage=-1):
        self.keyword, self.args, self.line, self.body, self.stage = keyword, args, line, body, stage


class Stage:
    def __init__(self, index, image, name, line):
        self.index, self.image, self.name, self.line = index, image, name, line
        self.instructions = []
        self.base_stage = None  # Stage this one builds on, when FROM names an earlier stage
        self.expanded = image
        self.unresolved = False


# ---------------------------------------------------------------- parsing

HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def parse(text: str):
    """Return (instructions, stages, global_args). Line numbers are 1-based and point at the first line."""
    lines = text.replace("\r\n", "\n").split("\n")
    instructions = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        start = i + 1
        logical = raw.rstrip()
        while logical.endswith("\\") and i + 1 < len(lines):
            logical = logical[:-1].rstrip()
            i += 1
            nxt = lines[i]
            while (not nxt.strip() or nxt.strip().startswith("#")) and i + 1 < len(lines):
                i += 1
                nxt = lines[i]
            logical += " " + nxt.strip().rstrip()
        logical = logical.rstrip("\\").strip()
        word, _, rest = logical.strip().partition(" ")
        keyword = word.upper()
        body = ""
        if keyword in ("RUN", "COPY", "ADD") and HEREDOC.search(rest):
            delimiters = [m.group(2) for m in HEREDOC.finditer(rest)]
            collected = []
            for delimiter in delimiters:
                i += 1
                while i < len(lines) and lines[i].strip().lstrip("\t") != delimiter:
                    collected.append(lines[i])
                    i += 1
            body = "\n".join(collected)
        instructions.append(Instruction(keyword, rest.strip(), start, body))
        i += 1
    global_args, stages, current = {}, [], None
    for ins in instructions:
        if ins.keyword == "FROM":
            tokens = [t for t in ins.args.split() if not t.startswith("--")]
            image = tokens[0] if tokens else ""
            name = tokens[2] if len(tokens) >= 3 and tokens[1].lower() == "as" else ""
            current = Stage(len(stages), image, name, ins.line)
            stages.append(current)
        ins.stage = current.index if current else -1
        if current is not None:
            current.instructions.append(ins)
        elif ins.keyword == "ARG":
            name, value = split_arg(ins.args)
            if name:
                global_args[name] = value
    by_name = {}
    for stage in stages:
        expanded, unresolved = expand(stage.image, global_args)
        stage.expanded, stage.unresolved = expanded, unresolved
        base = by_name.get(stage.image.lower())
        if base is not None:
            stage.base_stage = base
        if stage.name:
            by_name[stage.name.lower()] = stage
    return instructions, stages, global_args


def split_arg(args: str):
    token = args.split()[0] if args.split() else ""
    name, sep, value = token.partition("=")
    return name, (value.strip("'\"") if sep else None)


def expand(value: str, scope: dict):
    """Expand ${VAR}, ${VAR:-d} and $VAR from scope. Returns (text, had_unresolved_reference)."""
    unresolved = [False]

    def repl(match):
        name = match.group(1) or match.group(3)
        default = match.group(2)
        found = scope.get(name)
        if found:
            return found
        if default is not None:
            return default
        unresolved[0] = True
        return match.group(0)

    out = re.sub(r"\$\{(\w+)(?::?[-+]([^}]*))?\}|\$(\w+)", lambda m: repl(m), value)
    return out, unresolved[0]


def shell_text(ins: Instruction) -> str:
    text = ins.args
    if text.startswith("["):
        try:
            data = json.loads(text)
            if isinstance(data, list):
                text = " ".join(str(x) for x in data)
        except ValueError:
            pass
    return (text + ("\n" + ins.body if ins.body else "")).strip()


def commands(text: str) -> list:
    return [c.strip() for c in re.split(r"&&|\|\||;|\n", text) if c.strip()]


def tokens(args: str) -> list:
    try:
        return shlex.split(args, posix=True)
    except ValueError:
        return args.split()


def env_pairs(args: str) -> list:
    parts = tokens(args)
    if not parts:
        return []
    if "=" in parts[0]:
        return [tuple(p.split("=", 1)) for p in parts if "=" in p]
    return [(parts[0], " ".join(parts[1:]))]


def mask(value: str) -> str:
    value = value.strip()
    return value[:4] + "****" + value[-2:] if len(value) >= 12 else "****"


# ---------------------------------------------------------------- stage helpers

def shipped_stages(stages: list) -> set:
    """Indexes of stages whose layers end up in the final image (final + stages it builds on)."""
    shipped = set()
    stage = stages[-1] if stages else None
    while stage is not None and stage.index not in shipped:
        shipped.add(stage.index)
        stage = stage.base_stage
    return shipped


def final_chain(stages: list) -> list:
    chain, stage = [], stages[-1] if stages else None
    while stage is not None and stage not in chain:
        chain.append(stage)
        stage = stage.base_stage
    return list(reversed(chain))  # base first


def last_instruction(stages: list, keyword: str):
    for stage in reversed(final_chain(stages)):
        for ins in reversed(stage.instructions):
            if ins.keyword == keyword:
                return ins
    return None


# ---------------------------------------------------------------- .dockerignore

def ignore_entries(text: str) -> list:
    entries = []
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        if not line or line.startswith(("#", "!")):
            continue
        line = line.lstrip("/")
        while line.startswith("**/"):
            line = line[3:]
        entries.append(re.sub(r"/\*\*$", "", line.rstrip("/")))
    return entries


def covered(entries: list, name: str) -> bool:
    return any(entry == "*" or fnmatch.fnmatch(name, entry) for entry in entries)


# ---------------------------------------------------------------- checks

def lint_text(text: str, path: str = "Dockerfile", dockerignore=None, context_has=None) -> list:
    """Lint one Dockerfile's text. `dockerignore` is its text or None; `context_has` lists context files."""
    instructions, stages, global_args = parse(text)
    findings = []
    context_has = set(context_has or ())

    def add(rule, line, message, severity=None):
        name, default, fix = RULES[rule]
        findings.append({"file": path, "line": line, "rule": rule, "name": name,
                         "severity": severity or default, "message": message, "fix": fix})

    if not stages:
        return findings
    shipped = shipped_stages(stages)
    final = stages[-1]
    stage_names = {s.name.lower() for s in stages if s.name}

    # base images
    tag_only = []
    for stage in stages:
        image = stage.expanded
        if (not image or image.lower() == "scratch" or image.lower() in stage_names or stage.unresolved
                or stage.base_stage is not None):
            continue
        if "@sha256:" in image:
            continue
        last = image.rsplit("/", 1)[-1]
        if ":" not in last:
            add("DL001", stage.line, f"base image {image} has no tag, so it is :latest")
        elif last.endswith(":latest"):
            add("DL001", stage.line, f"base image {image} uses the latest tag")
        else:
            tag_only.append((image, stage.line))
    if tag_only:
        shown = ", ".join(f"{img} (line {ln})" for img, ln in tag_only[:4])
        add("DL002", tag_only[0][1], f"base image pinned by tag only, not digest: {shown}")

    # final user
    user = None
    for stage in final_chain(stages):
        for ins in stage.instructions:
            if ins.keyword == "USER":
                user = ins
    if user is None:
        add("DL003", final.line, "the final image runs as root: no USER instruction")
    else:
        name = user.args.split()[0].split(":")[0].strip("'\"") if user.args.split() else ""
        if name in ("root", "0"):
            add("DL003", user.line, "the final image runs as root: USER " + user.args.split()[0])

    # healthcheck
    health = last_instruction(stages, "HEALTHCHECK")
    if health is None:
        add("DL011", final.line, "no HEALTHCHECK in the final image")

    # context-wide copies
    local_copy = False
    whole_copy = False
    for stage in stages:
        installed = False
        copied_all = None
        pip_cache_env = any(i.keyword == "ENV" and any(k == "PIP_NO_CACHE_DIR" for k, _v in env_pairs(i.args))
                            for i in stage.instructions)
        scope = dict(global_args)
        for ins in stage.instructions:
            kw = ins.keyword
            if kw == "ARG":
                name, value = split_arg(ins.args)
                if name and value is not None:
                    scope[name] = value
                _check_secret_arg(add, ins, name, value)
            elif kw == "ENV":
                for key, value in env_pairs(ins.args):
                    scope[key] = value
                    _check_secret_env(add, ins, key, value)
            elif kw in ("COPY", "ADD"):
                flags = {}
                _check_copy(add, ins, flags)
                if flags.get("local"):
                    local_copy = True
                if flags.get("whole"):
                    whole_copy = True
                    if copied_all is None and not installed:
                        copied_all = ins
            elif kw == "EXPOSE":
                ports = [p.split("/")[0] for p in ins.args.split()]
                if "22" in ports:
                    add("DL012", ins.line, "EXPOSE 22: this image is set up to accept SSH")
            elif kw == "RUN":
                text = shell_text(ins)
                is_shipped = stage.index in shipped
                if PIPE_SHELL.search(text):
                    add("DL005", ins.line, "downloads a script and pipes it straight into a shell")
                _check_apt(add, ins, text, is_shipped)
                if re.search(r"(?<![\w-])sudo\b", text):
                    add("DL015", ins.line, "sudo in a RUN instruction")
                if re.search(r"\bchmod\s+(?:-\w+\s+)*(?:0?777|a\+rwx|ugo\+rwx|o\+w)\b", text):
                    add("DL016", ins.line, "chmod 777 makes files writable by every user")
                if INSTALL_CMD.search(text):
                    if copied_all is not None and not installed and not _installs_local(text):
                        add("DL009", copied_all.line,
                            f"COPY of the whole context (line {copied_all.line}) comes before the dependency install on line {ins.line}")
                        copied_all = None
                    installed = True
                _check_installs(add, ins, text, is_shipped, pip_cache_env)
            elif kw in ("CMD", "ENTRYPOINT") and stage is final:
                _check_shell_form(add, ins)

    _check_dockerignore(add, instructions, text, dockerignore, context_has, local_copy, whole_copy)
    findings.sort(key=lambda f: (f["line"], f["rule"], f["message"]))
    return findings


def _installs_local(text: str) -> bool:
    """`pip install .` and `pip install -e .` need the source tree, so they belong after COPY . ."""
    for cmd in commands(text):
        if re.search(r"\bpip3?\s+install\b", cmd) and re.search(r"(?:^|\s)(?:\.|\./\S*|-e)(?:\s|$)", cmd):
            return True
    return False


def _check_secret_env(add, ins, key, value):
    for pattern in VALUE_PATTERNS:
        if pattern.search(value):
            add("DL010", ins.line, f"ENV {key} holds a credential: {mask(value)}")
            return
    if SECRET_ENV.search(key) and not NOT_SECRET.search(key):
        if not value.strip() or PLACEHOLDER.search(value):
            return
        if re.fullmatch(r"\$\{?\w+\}?", value.strip()):
            add("DL010", ins.line, f"ENV {key} copies a build argument into the image, where `docker history` and `docker inspect` show it")
        else:
            add("DL010", ins.line, f"ENV {key} sets a secret-looking value in the image: {mask(value)}")


def _check_secret_arg(add, ins, name, value):
    if value is not None:
        for pattern in VALUE_PATTERNS:
            if pattern.search(value):
                add("DL010", ins.line, f"ARG {name} holds a credential: {mask(value)}")
                return
    if name and SECRET_ENV.search(name) and not NOT_SECRET.search(name):
        if value is None or not value or PLACEHOLDER.search(value):
            add("DL010", ins.line, f"ARG {name} is a build argument for a secret; build args are visible in `docker history`",
                "medium")
        else:
            add("DL010", ins.line, f"ARG {name} has a secret-looking default: {mask(value)}")


def _check_copy(add, ins, flags):
    if ins.body:  # heredoc COPY creates a file from inline text
        return
    parts = tokens(ins.args) if not ins.args.startswith("[") else _json_args(ins.args)
    options = [p for p in parts if p.startswith("--")]
    sources = [p for p in parts if not p.startswith("--")]
    if len(sources) < 2:
        return
    sources = sources[:-1]
    from_stage = any(o.startswith("--from") for o in options)
    if from_stage:
        return
    flags["local"] = True
    if any(s.rstrip("/") in (".", "*", "./*", "./") or s in (".", "./") for s in sources):
        flags["whole"] = True
    for source in sources:
        if SECRET_FILE.search(source.replace("\\", "/")):
            add("DL020", ins.line, f"{ins.keyword} puts {source} into the image")
    if ins.keyword == "ADD":
        has_checksum = any(o.startswith("--checksum") for o in options)
        for source in sources:
            if re.match(r"(?i)(https?://|git@|git://)", source):
                if not has_checksum:
                    add("DL004", ins.line, f"ADD downloads {source} with no checksum")
            elif not ARCHIVE.search(source):
                add("DL004", ins.line, f"ADD {source} copies a local file; COPY says what you mean")


def _json_args(text: str) -> list:
    try:
        data = json.loads(text)
        return [str(x) for x in data] if isinstance(data, list) else text.split()
    except ValueError:
        return text.split()


def _check_apt(add, ins, text, is_shipped):
    saw_update = saw_install = False
    for cmd in commands(text):
        if re.search(r"\bapt(?:-get)?\s+(?:-\S+\s+)*update\b", cmd):
            saw_update = True
        if re.search(r"\bapt(?:-get)?\s+(?:-\S+\s+)*install\b", cmd):
            saw_install = True
            if is_shipped and "no-install-recommends" not in cmd and "Install-Recommends=false" not in cmd:
                add("DL006", ins.line, "apt-get install without --no-install-recommends")
    if saw_update and not saw_install:
        add("DL008", ins.line, "apt-get update in its own RUN layer; the cached layer will go stale")
    if saw_install and is_shipped and not re.search(r"rm\s+(?:-\w+\s+)*/var/lib/apt/lists", text):
        add("DL007", ins.line, "apt package lists are left in the layer")


def _check_installs(add, ins, text, is_shipped, pip_cache_env):
    for cmd in commands(text):
        if re.search(r"(?:\bpip3?|python3?\s+-m\s+pip)\s+install\b", cmd):
            if is_shipped and "--no-cache-dir" not in cmd and not pip_cache_env:
                add("DL017", ins.line, "pip install keeps the download cache in the layer")
            parts = [p for p in cmd.split() if p]
            has_req = any(p in ("-r", "--requirement", "-c", "--constraint", "--require-hashes") or
                          p.startswith(("--requirement=", "--constraint=")) for p in parts)
            after = parts[parts.index("install") + 1:] if "install" in parts else []
            skip_next = False
            unpinned = []
            for part in after:
                if skip_next:
                    skip_next = False
                    continue
                if part in ("-r", "-c", "-e", "--index-url", "-i", "--extra-index-url", "-f", "--target", "-t"):
                    skip_next = True
                    continue
                if part.startswith("-") or part in (".", "$") or re.search(r"[=<>~@/.$]", part):
                    continue
                unpinned.append(part)
            if unpinned and not has_req:
                add("DL018", ins.line, "pip install of unpinned packages: " + ", ".join(unpinned[:4]))
        elif re.search(r"\bnpm\s+(?:install|i)\b", cmd):
            parts = cmd.split()
            names = [p for p in parts[parts.index("install" if "install" in parts else "i") + 1:] if not p.startswith("-")]
            if not names:
                add("DL018", ins.line, "npm install may rewrite the lockfile; npm ci installs exactly what it records and fails on drift")
            elif any(not re.search(r"@[\w^~<>=.*-]+$", n.lstrip("@")) for n in names) and "-g" in parts:
                add("DL018", ins.line, "npm install -g without a version: " + ", ".join(names[:4]))
        elif re.search(r"\byarn\s+install\b", cmd) and not re.search(r"--frozen-lockfile|--immutable", cmd):
            add("DL018", ins.line, "yarn install without --frozen-lockfile (or --immutable)")
        elif re.search(r"\bpnpm\s+(?:install|i)\b", cmd) and "--frozen-lockfile" not in cmd:
            add("DL018", ins.line, "pnpm install without --frozen-lockfile")


def _check_shell_form(add, ins):
    text = ins.args.strip()
    if not text or text.startswith("["):
        parts = _json_args(text) if text else []
        if len(parts) >= 3 and parts[0] in ("sh", "bash", "/bin/sh", "/bin/bash") and parts[1] == "-c" \
                and not parts[2].lstrip().startswith("exec "):
            add("DL019", ins.line, f"{ins.keyword} runs through `{parts[0]} -c` without exec, so the shell stays PID 1")
        return
    if text.startswith("exec "):
        return
    add("DL019", ins.line, f"{ins.keyword} is in shell form, so the process runs under /bin/sh -c and may miss SIGTERM")


def _check_dockerignore(add, instructions, text, dockerignore, context_has, local_copy, whole_copy):
    if not local_copy:
        return
    if dockerignore is None:
        add("DL013", 0, "no .dockerignore: the whole folder, including .git and .env, is sent as build context")
        return
    entries = ignore_entries(dockerignore)
    wanted = [".git", ".env"]
    uses_node = "package.json" in context_has or re.search(r"\b(?:npm|yarn|pnpm|node)\b", text)
    if uses_node:
        wanted.append("node_modules")
    missing = [w for w in wanted if not covered(entries, w)]
    if missing:
        add("DL014", 0, ".dockerignore does not exclude: " + ", ".join(missing))


# ---------------------------------------------------------------- files

def is_dockerfile_name(name: str) -> bool:
    low = name.lower()
    return (low in ("dockerfile", "containerfile") or low.startswith(("dockerfile.", "containerfile."))
            or low.endswith((".dockerfile", ".containerfile")))


def discover(path: Path) -> list:
    if path.is_file():
        return [path]
    found = []
    globs = load_ignore(path)
    for folder, dirs, files in os.walk(path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            candidate = Path(folder) / name
            if (is_dockerfile_name(name) and not name.lower().endswith(".dockerignore")
                    and not path_ignored(candidate.relative_to(path).as_posix(), globs)):
                found.append(candidate)
    return found


def lint_file(path: Path, rel: str) -> list:
    text = path.read_bytes().decode("utf-8-sig", "replace")
    folder = path.parent
    per_file = folder / (path.name + ".dockerignore")
    shared = folder / ".dockerignore"
    ignore_path = per_file if per_file.is_file() else shared if shared.is_file() else None
    ignore = ignore_path.read_bytes().decode("utf-8", "replace") if ignore_path else None
    context = {p.name for p in folder.iterdir()} if folder.is_dir() else set()
    return lint_text(text, rel, ignore, context)


def run(paths: list) -> dict:
    findings, files = [], []
    for given in paths:
        given = Path(given)
        for found in discover(given):
            rel = found.relative_to(given).as_posix() if given.is_dir() else found.as_posix()
            files.append(rel)
            findings.extend(lint_file(found, rel))
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    counts = Counter(f["severity"] for f in findings)
    return {"tool": "dockerfile_lint", "dockerfiles": sorted(files),
            "counts": {s: counts.get(s, 0) for s in SEVERITIES}, "findings": findings}


def format_text(result: dict) -> str:
    c = result["counts"]
    n = len(result["dockerfiles"])
    lines = [f"shipcheck docker: {n} Dockerfile{'s' if n != 1 else ''}, {len(result['findings'])} findings "
             f"({c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info)"]
    for f in result["findings"]:
        where = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        lines.append(f"{where}  {f['rule']}  {f['severity']:<6}  {f['message']}")
        lines.append(f"    fix: {f['fix']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="dockerfile_lint.py", description="Lint Dockerfiles and their .dockerignore.")
    parser.add_argument("path", nargs="*", default=["."], help="Dockerfile(s) or folder(s) to search (default: .)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    parser.add_argument("--fail-on", default="high", choices=["high", "medium", "low", "info", "never"],
                        help="exit 1 when a finding at or above this severity exists (default: high)")
    parser.add_argument("--list-rules", action="store_true", help="print rule ids and exit")
    args = parser.parse_args(argv)
    if args.list_rules:
        for rule, (name, severity, _fix) in sorted(RULES.items()):
            print(f"{rule}  {severity:<6}  {name}")
        return 0
    missing = [p for p in args.path if not Path(p).exists()]
    if missing:
        print(f"error: {missing[0]} does not exist", file=sys.stderr)
        return 2
    result = run(args.path)
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
