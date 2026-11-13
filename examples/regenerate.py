#!/usr/bin/env python3
"""Regenerate (or verify) examples/output/*.md by running every shipcheck script on the demo app.

  python examples/regenerate.py                         rewrite examples/output/
  python examples/regenerate.py --check                 exit 1 if the committed outputs are stale
  python examples/regenerate.py --materialize [DIR]     build the demo workspace in DIR
                                                        (default .shipcheck-demo, git-ignored)

The committed tree (examples/sample-app) holds no secrets. The fake credentials are assembled
here, at run time, from fragments, and only ever written to a temporary or git-ignored folder.
Every value the scripts print is masked, so the committed outputs are safe to publish.
Standard library only.
"""
from __future__ import annotations

import argparse
import importlib.util
import io
import shutil
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "examples" / "sample-app"
OUTPUT = ROOT / "examples" / "output"
DEFAULT_WORKSPACE = ".shipcheck-demo"
MARKER = ".shipcheck-demo-workspace"


def _load(skill: str, script: str):
    path = ROOT / "skills" / skill / f"{script}.py"
    spec = importlib.util.spec_from_file_location(f"_regen_{script}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def runtime_files() -> dict:
    """Fake credentials, built from fragments so that no complete token exists in this repository."""
    aws_id = "AKIA" + "QX7M2KD9RT4VBN3H"
    aws_secret = "k3Jv9sQ2mXw8Lp5T" + "zR7bN4cY6hG1dF0a" + "E+uVxW2q"
    hook = "https://hooks.slack.com/services/" + "T0123ABCD/B0456EFGH/" + "Qw3rTy7uIo9pAs5dFg2hJk4l"
    gh = "ghp_" + "a1B2c3D4e5F6g7H8" + "i9J0k1L2m3N4o5P6q7R8"
    stripe = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
    db_url = "postgres://app:" + "Tr0ub4dor" + "9xQ" + "@db.prod.internal:5432/app"
    pem_head = "-----BEGIN RSA PRIV" + "ATE KEY-----"
    pem_foot = "-----END RSA PRIV" + "ATE KEY-----"
    pem_body = ["MIIEowIBAAKCAQEA" + "x7Qm2LkR9vTnB4cY", "n3Kp8Wz1Vb6Lq0Ds" + "Hj5Fg2Tr9Mc4XyA"]
    return {
        "config/settings.py": "\n".join([
            "# Pasted in a hurry during an outage. Do not do this.",
            f'AWS_ACCESS_KEY_ID = "{aws_id}"',
            f'AWS_SECRET_ACCESS_KEY = "{aws_secret}"',
            f'SLACK_WEBHOOK = "{hook}"',
            ""]),
        "scripts/notify.sh": "\n".join(["#!/bin/sh", f"export GITHUB_TOKEN={gh}", "./notify --channel ops", ""]),
        "deploy/id_rsa": "\n".join([pem_head, *pem_body, pem_foot, ""]),
        ".env": "\n".join([
            f"DATABASE_URL={db_url}", "JWT_SECRET=", "PORT=3000", f"STRIPE_SECRET_KEY={stripe}",
            "INTERNAL_FEATURE_X=on", ""]),
    }


def materialize(dest: Path) -> list:
    """Copy examples/sample-app into `dest` and add the runtime-assembled fake secret files."""
    dest = Path(dest)
    if dest.exists():
        if any(dest.iterdir()) and not (dest / MARKER).exists():
            raise ValueError(f"{dest} exists and was not created by this script; refusing to delete it")
        shutil.rmtree(dest)
    shutil.copytree(SAMPLE, dest)
    (dest / MARKER).write_bytes(b"")
    written = []
    for rel, text in runtime_files().items():
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))
        written.append(rel)
    return sorted(written)


def capture(func, argv: list) -> tuple:
    out = io.StringIO()
    with redirect_stdout(out):
        code = func(argv)
    return code, out.getvalue().rstrip("\n")


def document(title: str, command: str, code: int, text: str) -> str:
    return "\n".join([
        f"# {title}", "",
        "Run against the demo workspace built by `python examples/regenerate.py --materialize`.", "",
        "```", f"$ {command}", "```", "",
        "```text", text, "```", "",
        f"Exit code: {code}", ""])


def generate(out: Path) -> list:
    """Build the workspace in a temp folder, run every script, write the Markdown outputs to `out`."""
    secrets = _load("shipcheck-secrets", "secrets_scan")
    env = _load("shipcheck-env", "env_audit")
    docker = _load("shipcheck-docker", "dockerfile_lint")
    ci = _load("shipcheck-ci", "ci_audit")
    preflight = _load("shipcheck-preflight", "preflight")
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    steps = [
        ("secrets.md", "shipcheck-secrets", "python skills/shipcheck-secrets/secrets_scan.py .shipcheck-demo",
         secrets.main, ["{ws}"]),
        ("env.md", "shipcheck-env", "python skills/shipcheck-env/env_audit.py .shipcheck-demo",
         env.main, ["{ws}"]),
        ("env-suggest.md", "shipcheck-env --suggest", "python skills/shipcheck-env/env_audit.py .shipcheck-demo --suggest",
         env.main, ["{ws}", "--suggest"]),
        ("docker.md", "shipcheck-docker", "python skills/shipcheck-docker/dockerfile_lint.py .shipcheck-demo",
         docker.main, ["{ws}"]),
        ("ci.md", "shipcheck-ci", "python skills/shipcheck-ci/ci_audit.py .shipcheck-demo",
         ci.main, ["{ws}"]),
        ("preflight.md", "shipcheck-preflight", "python skills/shipcheck-preflight/preflight.py .shipcheck-demo",
         preflight.main, ["{ws}"]),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        workspace = Path(tmp) / "demo"
        materialize(workspace)
        for name, title, command, func, argv in steps:
            code, text = capture(func, [a.replace("{ws}", str(workspace)) for a in argv])
            (out / name).write_bytes(document(title, command, code, text).encode("utf-8"))
    return sorted(p.name for p in out.iterdir() if p.is_file())


def compare(expected_dir: Path, actual_dir: Path) -> list:
    """Return a list of differences between two output folders."""
    problems = []
    expected = {p.name for p in Path(expected_dir).glob("*") if p.is_file()}
    actual = {p.name for p in Path(actual_dir).glob("*") if p.is_file()}
    for name in sorted(expected ^ actual):
        problems.append(f"{name}: {'missing from regenerated output' if name in expected else 'not committed'}")
    for name in sorted(expected & actual):
        if (Path(expected_dir) / name).read_bytes() != (Path(actual_dir) / name).read_bytes():
            problems.append(f"{name}: content differs")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="verify instead of rewriting")
    parser.add_argument("--materialize", nargs="?", const=DEFAULT_WORKSPACE, metavar="DIR",
                        help="build the demo workspace (with runtime-assembled fake secrets) in DIR and exit")
    args = parser.parse_args(argv)
    if args.materialize:
        target = Path(args.materialize)
        if target.resolve() in (ROOT, SAMPLE, ROOT / "examples"):
            print("error: refusing to overwrite the repository", file=sys.stderr)
            return 2
        try:
            extra = materialize(target)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"built {target.as_posix()} from examples/sample-app, plus runtime files: {', '.join(extra)}")
        print("these files hold fake credentials; the folder is git-ignored, do not commit it")
        return 0
    if not args.check:
        for name in generate(OUTPUT):
            print(f"wrote examples/output/{name}")
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        generate(Path(tmp))
        problems = compare(OUTPUT, Path(tmp))
    for problem in problems:
        print(problem)
    print("examples/output is up to date" if not problems else f"{len(problems)} stale file(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
