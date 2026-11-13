"""Tests for skills/shipcheck-docker/dockerfile_lint.py."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from _load import load, write

dl = load("shipcheck-docker", "dockerfile_lint")

GOOD = """FROM python:3.12-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000
RUN useradd -m app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER app
HEALTHCHECK CMD python -c "print(1)"
CMD ["python", "app.py"]
"""
IGNORE = ".git\n.env\nnode_modules\n"


def lint(text, ignore=IGNORE, context=()):
    return dl.lint_text(text, "Dockerfile", ignore, context)


def ids(findings):
    return sorted({f["rule"] for f in findings if f["rule"] != "DL002"})


def by_rule(findings, rule):
    return [f for f in findings if f["rule"] == rule]


class ParserTests(unittest.TestCase):
    def test_continuations_comments_and_line_numbers(self):
        text = "FROM a:1\n# comment\nRUN one \\\n  # inner comment\n  && two \\\n\n  && three\nCMD [\"x\"]\n"
        ins, stages, _ = dl.parse(text)
        self.assertEqual([(i.keyword, i.line) for i in ins], [("FROM", 1), ("RUN", 3), ("CMD", 8)])
        self.assertEqual(ins[1].args, "one  && two  && three".replace("  ", " "))
        self.assertEqual(len(stages), 1)

    def test_crlf(self):
        ins, _, _ = dl.parse("FROM a:1\r\nRUN x \\\r\n  && y\r\n")
        self.assertEqual(ins[1].args, "x && y")

    def test_heredoc_body_is_attached_and_skipped(self):
        text = "FROM a:1\nRUN <<EOF\ncurl https://x.example | sh\nEOF\nCOPY <<-'END' /etc/f\n\tcontent\n\tEND\nUSER app\n"
        ins, _, _ = dl.parse(text)
        self.assertEqual([i.keyword for i in ins], ["FROM", "RUN", "COPY", "USER"])
        self.assertIn("curl https://x.example | sh", ins[1].body)
        self.assertEqual(ins[3].line, 8)
        findings = lint(text)
        self.assertEqual([f["line"] for f in by_rule(findings, "DL005")], [2])

    def test_stages_and_global_args(self):
        text = "ARG BASE=python:3.12\nARG V\nFROM ${BASE} AS build\nFROM build AS final\nFROM --platform=$BUILDPLATFORM golang AS go\n"
        _, stages, args = dl.parse(text)
        self.assertEqual(args, {"BASE": "python:3.12", "V": None})
        self.assertEqual([s.name for s in stages], ["build", "final", "go"])
        self.assertEqual(stages[0].expanded, "python:3.12")
        self.assertIs(stages[1].base_stage, stages[0])
        self.assertEqual(stages[2].image, "golang")

    def test_expand(self):
        self.assertEqual(dl.expand("a:${V:-1}-$W", {"W": "x"}), ("a:1-x", False))
        self.assertEqual(dl.expand("a:$MISSING", {}), ("a:$MISSING", True))

    def test_env_pairs(self):
        self.assertEqual(dl.env_pairs('A=1 B="two words"'), [("A", "1"), ("B", "two words")])
        self.assertEqual(dl.env_pairs("LEGACY some value"), [("LEGACY", "some value")])


class CleanFileTests(unittest.TestCase):
    def test_good_dockerfile_has_no_findings(self):
        self.assertEqual(lint(GOOD, context={"requirements.txt"}), [])


class BaseImageTests(unittest.TestCase):
    def test_latest_and_untagged(self):
        self.assertEqual([f["line"] for f in by_rule(lint("FROM node\nUSER a\n"), "DL001")], [1])
        self.assertEqual(len(by_rule(lint("FROM node:latest\nUSER a\n"), "DL001")), 1)
        self.assertEqual(len(by_rule(lint("FROM registry.example:5000/team/app\nUSER a\n"), "DL001")), 1)
        self.assertEqual(by_rule(lint("FROM registry.example:5000/team/app:1.2\nUSER a\n"), "DL001"), [])

    def test_tag_only_is_an_info_advisory(self):
        found = by_rule(lint("FROM node:20-alpine AS a\nFROM nginx:1.25\nUSER a\n"), "DL002")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "info")
        self.assertIn("node:20-alpine (line 1)", found[0]["message"])
        self.assertEqual(by_rule(lint("FROM node:20@sha256:" + "a" * 64 + "\nUSER a\n"), "DL002"), [])

    def test_scratch_stage_references_and_unresolved_args_are_skipped(self):
        text = "ARG IMG\nFROM scratch AS base\nFROM base\nFROM ${IMG}\nUSER a\n"
        self.assertEqual(by_rule(lint(text), "DL001"), [])

    def test_global_arg_is_expanded(self):
        self.assertEqual(len(by_rule(lint("ARG TAG=latest\nFROM node:${TAG}\nUSER a\n"), "DL001")), 1)
        self.assertEqual(by_rule(lint("ARG TAG=20\nFROM node:${TAG}\nUSER a\n"), "DL001"), [])


class UserAndHealthTests(unittest.TestCase):
    def test_no_user_and_root_user(self):
        self.assertEqual(len(by_rule(lint("FROM a:1\n"), "DL003")), 1)
        self.assertEqual(len(by_rule(lint("FROM a:1\nUSER root\n"), "DL003")), 1)
        self.assertEqual(len(by_rule(lint("FROM a:1\nUSER 0:0\n"), "DL003")), 1)
        self.assertEqual(by_rule(lint("FROM a:1\nUSER 1000\n"), "DL003"), [])
        self.assertEqual(len(by_rule(lint("FROM a:1\nUSER app\nUSER root\n"), "DL003")), 1)

    def test_only_the_final_stage_counts(self):
        text = "FROM a:1 AS build\nUSER root\nRUN make\nFROM b:1\nUSER app\n"
        self.assertEqual(by_rule(lint(text), "DL003"), [])
        text = "FROM a:1 AS build\nUSER app\nFROM b:1\nRUN x\n"
        self.assertEqual(len(by_rule(lint(text), "DL003")), 1)

    def test_user_is_inherited_from_a_named_base_stage(self):
        text = "FROM a:1 AS base\nUSER app\nFROM base AS final\nRUN x\n"
        self.assertEqual(by_rule(lint(text), "DL003"), [])

    def test_healthcheck(self):
        self.assertEqual(by_rule(lint("FROM a:1\nUSER a\nHEALTHCHECK NONE\n"), "DL011"), [])
        found = by_rule(lint("FROM a:1\nUSER a\n"), "DL011")
        self.assertEqual((found[0]["severity"], found[0]["line"]), ("info", 1))


class RunRuleTests(unittest.TestCase):
    def run_rules(self, run_line, extra=""):
        return lint("FROM a:1\n" + extra + run_line + "\nUSER a\n")

    def test_pipe_to_shell_variants(self):
        for cmd in ("curl -fsSL https://x.example/i.sh | sh", "curl -s https://x.example | sudo bash",
                    "wget -qO- https://x.example | bash -s -- -y", "bash -c \"$(curl -fsSL https://x.example)\"",
                    "bash <(curl -s https://x.example)", "curl https://x.example | python3 -"):
            with self.subTest(cmd=cmd):
                found = by_rule(self.run_rules("RUN " + cmd), "DL005")
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0]["severity"], "high")
        self.assertEqual(by_rule(self.run_rules("RUN curl -fsSLo /tmp/i.sh https://x.example && sha256sum -c i.sum"), "DL005"), [])

    def test_apt_rules(self):
        bad = self.run_rules("RUN apt-get update && apt-get install -y curl")
        self.assertEqual(ids(bad), ["DL006", "DL007", "DL011"])
        good = self.run_rules("RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*")
        self.assertEqual(ids(good), ["DL011"])
        self.assertEqual(len(by_rule(self.run_rules("RUN apt-get update"), "DL008")), 1)
        self.assertEqual(by_rule(self.run_rules("RUN apt-get update && apt-get install -y x"), "DL008"), [])
        self.assertEqual(len(by_rule(self.run_rules("RUN apt install -y x"), "DL006")), 1)

    def test_layer_hygiene_ignored_for_builder_stages(self):
        text = "FROM a:1 AS build\nRUN apt-get update && apt-get install -y gcc\nFROM b:1\nUSER app\n"
        self.assertEqual(by_rule(lint(text), "DL006"), [])
        self.assertEqual(by_rule(lint(text), "DL007"), [])
        text = "FROM a:1 AS base\nRUN apt-get update && apt-get install -y gcc\nFROM base\nUSER app\n"
        self.assertEqual(len(by_rule(lint(text), "DL006")), 1)

    def test_sudo_and_chmod(self):
        self.assertEqual(len(by_rule(self.run_rules("RUN sudo apt-get x"), "DL015")), 1)
        self.assertEqual(by_rule(self.run_rules("RUN echo pseudo-sudoers"), "DL015"), [])
        for cmd in ("chmod 777 /app", "chmod -R 777 /app", "chmod a+rwx /x"):
            self.assertEqual(len(by_rule(self.run_rules("RUN " + cmd), "DL016")), 1, cmd)
        self.assertEqual(by_rule(self.run_rules("RUN chmod 755 /app"), "DL016"), [])

    def test_pip(self):
        self.assertEqual(len(by_rule(self.run_rules("RUN pip install -r requirements.txt"), "DL017")), 1)
        self.assertEqual(by_rule(self.run_rules("RUN pip install --no-cache-dir -r requirements.txt"), "DL017"), [])
        self.assertEqual(by_rule(self.run_rules("RUN pip install -r requirements.txt", "ENV PIP_NO_CACHE_DIR=1\n"), "DL017"), [])
        self.assertEqual(len(by_rule(self.run_rules("RUN pip install --no-cache-dir flask gunicorn==21.2.0"), "DL018")), 1)
        self.assertEqual(by_rule(self.run_rules("RUN pip install --no-cache-dir flask==3.0.0"), "DL018"), [])
        self.assertEqual(by_rule(self.run_rules("RUN pip install --no-cache-dir -r requirements.txt"), "DL018"), [])
        self.assertEqual(by_rule(self.run_rules("RUN pip install --no-cache-dir ."), "DL018"), [])

    def test_node_installs(self):
        self.assertEqual(len(by_rule(self.run_rules("RUN npm install"), "DL018")), 1)
        self.assertEqual(by_rule(self.run_rules("RUN npm ci"), "DL018"), [])
        self.assertEqual(len(by_rule(self.run_rules("RUN npm install -g typescript"), "DL018")), 1)
        self.assertEqual(by_rule(self.run_rules("RUN npm install -g typescript@5.4.2"), "DL018"), [])
        self.assertEqual(len(by_rule(self.run_rules("RUN yarn install"), "DL018")), 1)
        self.assertEqual(by_rule(self.run_rules("RUN yarn install --frozen-lockfile"), "DL018"), [])
        self.assertEqual(len(by_rule(self.run_rules("RUN pnpm install"), "DL018")), 1)

    def test_exec_form_run(self):
        self.assertEqual(len(by_rule(self.run_rules('RUN ["sh", "-c", "curl https://x.example | sh"]'), "DL005")), 1)


class CopyTests(unittest.TestCase):
    def test_add_vs_copy(self):
        base = "FROM a:1\nUSER a\n"
        self.assertEqual(len(by_rule(lint(base + "ADD app.py /app/\n"), "DL004")), 1)
        self.assertEqual(by_rule(lint(base + "ADD rootfs.tar.gz /\n"), "DL004"), [])
        self.assertEqual(len(by_rule(lint(base + "ADD https://x.example/f.bin /f\n"), "DL004")), 1)
        self.assertEqual(by_rule(lint(base + "ADD --checksum=sha256:abc https://x.example/f.bin /f\n"), "DL004"), [])
        self.assertEqual(by_rule(lint(base + "COPY app.py /app/\n"), "DL004"), [])

    def test_copy_all_before_install_is_cache_busting(self):
        bad = "FROM node:20\nUSER a\nCOPY . .\nRUN npm ci\n"
        found = by_rule(lint(bad), "DL009")
        self.assertEqual([f["line"] for f in found], [3])
        good = "FROM node:20\nUSER a\nCOPY package.json package-lock.json ./\nRUN npm ci\nCOPY . .\n"
        self.assertEqual(by_rule(lint(good), "DL009"), [])
        self.assertEqual(len(by_rule(lint("FROM a:1\nUSER a\nCOPY . /app\nRUN pip install --no-cache-dir -r requirements.txt\n"), "DL009")), 1)

    def test_editable_install_needs_the_source(self):
        text = "FROM a:1\nUSER a\nCOPY . .\nRUN pip install --no-cache-dir .\n"
        self.assertEqual(by_rule(lint(text), "DL009"), [])

    def test_copy_from_another_stage_is_not_the_context(self):
        text = "FROM a:1 AS b\nFROM c:1\nUSER a\nCOPY --from=b /out /out\n"
        self.assertEqual(ids(lint(text, ignore=None)), ["DL011"])

    def test_secret_files_in_copy(self):
        for src in (".env", "id_rsa", "certs/server.pem", ".npmrc", ".aws/"):
            with self.subTest(src=src):
                self.assertEqual(len(by_rule(lint("FROM a:1\nUSER a\nCOPY " + src + " /app/\n"), "DL020")), 1)
        self.assertEqual(by_rule(lint("FROM a:1\nUSER a\nCOPY .env.example /app/\n"), "DL020"), [])

    def test_json_form_copy(self):
        self.assertEqual(len(by_rule(lint('FROM a:1\nUSER a\nCOPY [".env", "/app/"]\n'), "DL020")), 1)


class SecretTests(unittest.TestCase):
    def secret_findings(self, line):
        return by_rule(lint("FROM a:1\nUSER a\n" + line + "\n"), "DL010")

    def test_env_with_secret_value(self):
        found = self.secret_findings("ENV DB_PASSWORD=" + "hunter2" + "hunter2")
        self.assertEqual((found[0]["severity"], found[0]["line"]), ("high", 3))
        self.assertNotIn("hunter2hunter2", json.dumps(found))
        self.assertIn("hunt****r2", found[0]["message"])
        self.assertEqual(len(self.secret_findings("ENV API_KEY somevalue12345")), 1)

    def test_env_that_copies_a_build_arg(self):
        found = self.secret_findings("ENV NPM_TOKEN=${NPM_TOKEN}")
        self.assertEqual(len(found), 1)
        self.assertIn("build argument", found[0]["message"])

    def test_arg_secret(self):
        found = self.secret_findings("ARG GITHUB_TOKEN")
        self.assertEqual((found[0]["severity"]), "medium")
        self.assertEqual(len(self.secret_findings("ARG API_KEY=changeme")), 1)
        self.assertEqual(self.secret_findings("ARG BUILD_DATE"), [])

    def test_clean_env(self):
        for line in ("ENV DB_PASSWORD=", "ENV TOKEN_URL=https://x.example", "ENV PASSWORD_FILE=/run/secrets/pw",
                     "ENV SECRET_KEY=changeme", "ENV PUBLIC_KEY_PATH=/k", "ENV NODE_ENV=production"):
            with self.subTest(line=line):
                self.assertEqual(self.secret_findings(line), [])

    def test_credential_in_any_env_value(self):
        token = "ghp_" + "a1B2c3D4e5F6g7H8" + "i9J0k1L2m3N4o5P6q7R8"
        found = self.secret_findings("ENV SOMETHING=" + token)
        self.assertEqual(len(found), 1)
        self.assertNotIn(token, json.dumps(found))


class ExposeCmdTests(unittest.TestCase):
    def test_expose_22(self):
        self.assertEqual(len(by_rule(lint("FROM a:1\nUSER a\nEXPOSE 80 22/tcp\n"), "DL012")), 1)
        self.assertEqual(by_rule(lint("FROM a:1\nUSER a\nEXPOSE 80 2222\n"), "DL012"), [])

    def test_shell_form_cmd_and_entrypoint(self):
        text = "FROM a:1\nUSER a\nENTRYPOINT ./run.sh\nCMD npm start\n"
        self.assertEqual([f["line"] for f in by_rule(lint(text), "DL019")], [3, 4])
        self.assertEqual(by_rule(lint('FROM a:1\nUSER a\nCMD ["node", "server.js"]\n'), "DL019"), [])
        self.assertEqual(by_rule(lint("FROM a:1\nUSER a\nCMD exec node server.js\n"), "DL019"), [])
        self.assertEqual(len(by_rule(lint('FROM a:1\nUSER a\nCMD ["sh", "-c", "node server.js"]\n'), "DL019")), 1)
        self.assertEqual(by_rule(lint('FROM a:1\nUSER a\nCMD ["sh", "-c", "exec node server.js"]\n'), "DL019"), [])

    def test_only_final_stage_cmd(self):
        text = "FROM a:1 AS build\nCMD make\nFROM b:1\nUSER a\nCMD [\"run\"]\n"
        self.assertEqual(by_rule(lint(text), "DL019"), [])


class DockerignoreTests(unittest.TestCase):
    TEXT = "FROM node:20\nUSER a\nCOPY . .\n"

    def test_missing_dockerignore(self):
        found = by_rule(lint(self.TEXT, ignore=None), "DL013")
        self.assertEqual((found[0]["severity"], found[0]["line"]), ("medium", 0))

    def test_no_local_copy_means_no_dockerignore_finding(self):
        self.assertEqual(by_rule(lint("FROM a:1\nUSER a\nRUN true\n", ignore=None), "DL013"), [])

    def test_incomplete(self):
        found = by_rule(lint(self.TEXT, ignore="# c\ndist\n"), "DL014")
        self.assertEqual(found[0]["message"], ".dockerignore does not exclude: .git, .env, node_modules")
        found = by_rule(lint(self.TEXT, ignore=".git\n"), "DL014")
        self.assertIn(".env, node_modules", found[0]["message"])

    def test_patterns_that_cover(self):
        for text in (".git\n.env\nnode_modules\n", "**/.git\n**/.env*\n**/node_modules\n", "/.git/\n.env*\nnode_modules/\n",
                     ".*\nnode_modules\n", "*\n!src\n"):
            with self.subTest(text=text):
                self.assertEqual(by_rule(lint(self.TEXT, ignore=text), "DL014"), [])

    def test_node_modules_only_wanted_for_node_projects(self):
        text = "FROM python:3.12\nUSER a\nCOPY . .\n"
        self.assertEqual(by_rule(lint(text, ignore=".git\n.env\n"), "DL014"), [])
        self.assertEqual(len(by_rule(lint(text, ignore=".git\n.env\n", context={"package.json"}), "DL014")), 1)


class FilesAndCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = dl.main([str(a) for a in argv])
        return code, out.getvalue(), err.getvalue()

    def test_discovery_and_dockerignore_lookup(self):
        write(self.root, "Dockerfile", "FROM a:1\nUSER a\nCOPY . .\n")
        write(self.root, "services/api/Dockerfile.prod", "FROM a:1\nUSER a\nCOPY . .\n")
        write(self.root, "services/api/Dockerfile.prod.dockerignore", ".git\n.env\nnode_modules\n")
        write(self.root, "services/web/web.Dockerfile", "FROM a:1\nUSER a\n")
        write(self.root, "node_modules/pkg/Dockerfile", "FROM a\n")
        write(self.root, "notes/dockerfile-notes.txt", "FROM a\n")
        result = dl.run([self.root])
        self.assertEqual(result["dockerfiles"], ["Dockerfile", "services/api/Dockerfile.prod", "services/web/web.Dockerfile"])
        located = {(f["file"], f["rule"]) for f in result["findings"]}
        self.assertIn(("Dockerfile", "DL013"), located)
        self.assertNotIn(("services/api/Dockerfile.prod", "DL013"), located)
        self.assertNotIn(("services/api/Dockerfile.prod", "DL014"), located)

    def test_shared_dockerignore(self):
        write(self.root, "Dockerfile", "FROM a:1\nUSER a\nCOPY . .\n")
        write(self.root, ".dockerignore", ".git\n.env\n")
        self.assertEqual([f["rule"] for f in dl.run([self.root])["findings"] if f["rule"].startswith("DL01") and f["rule"] != "DL011"], [])

    def test_text_output_and_exit_code(self):
        write(self.root, "Dockerfile", "FROM node:latest\nRUN curl https://x.example | sh\n")
        code, out, _ = self.run_cli(self.root)
        self.assertEqual(code, 1)
        self.assertIn("shipcheck docker: 1 Dockerfile, ", out)
        self.assertIn("Dockerfile:2  DL005  high    downloads a script and pipes it straight into a shell", out)
        self.assertIn("    fix: ", out)

    def test_fail_on(self):
        write(self.root, "Dockerfile", "FROM node:latest\nUSER a\n")
        self.assertEqual(self.run_cli(self.root)[0], 0)
        self.assertEqual(self.run_cli(self.root, "--fail-on", "medium")[0], 1)
        self.assertEqual(self.run_cli(self.root, "--fail-on", "never")[0], 0)

    def test_json(self):
        write(self.root, "Dockerfile", "FROM node\n")
        code, out, _ = self.run_cli(self.root, "--json", "--fail-on", "never")
        data = json.loads(out)
        self.assertEqual(data["tool"], "dockerfile_lint")
        for key in ("file", "line", "rule", "name", "severity", "message", "fix"):
            self.assertIn(key, data["findings"][0])

    def test_explicit_file_and_missing_path(self):
        write(self.root, "Dockerfile.dev", "FROM node:20\nUSER a\n")
        code, out, _ = self.run_cli(self.root / "Dockerfile.dev", "--fail-on", "never")
        self.assertEqual(code, 0)
        self.assertIn("1 Dockerfile,", out)
        code, _, err = self.run_cli(self.root / "missing")
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)

    def test_empty_folder_and_list_rules(self):
        code, out, _ = self.run_cli(self.root)
        self.assertEqual(code, 0)
        self.assertIn("0 Dockerfiles, 0 findings", out)
        code, out, _ = self.run_cli("--list-rules")
        self.assertIn("DL001", out)
        self.assertIn("DL020", out)


class IgnoreFileTests(unittest.TestCase):
    def test_shipcheck_ignore_globs_skip_dockerfiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "Dockerfile", "FROM a:1\nUSER a\n")
            write(root, "examples/demo/Dockerfile", "FROM node\n")
            write(root, ".shipcheck-ignore", "examples/\n")
            self.assertEqual(dl.run([root])["dockerfiles"], ["Dockerfile"])
            self.assertEqual(len(dl.run([root / "examples" / "demo" / "Dockerfile"])["dockerfiles"]), 1)


if __name__ == "__main__":
    unittest.main()
