"""Tests for skills/shipcheck-env/env_audit.py."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from _load import load, write

ea = load("shipcheck-env", "env_audit")

REAL_VALUE = "Zq8" + "Lm4Tr7Wn2Kp9"  # assembled at runtime; never committed as one string


def reads(text, lang):
    found, dynamic = ea.read_source("x", text, lang)
    return {(name, fallback, strict) for name, _line, fallback, strict in found}, dynamic


class PythonReaderTests(unittest.TestCase):
    def test_reads(self):
        got, _ = reads('''
a = os.environ["A_REQ"]
b = os.environ.get("B_NOFB")
c = os.environ.get("C_FB", "x")
d = os.getenv("D_NOFB")
e = os.getenv("E_FB", "5")
f = os.getenv("F_NONE", None)
g = environ["G_REQ"]
h = os.environ.setdefault("H_FB", "1")
''', "python")
        self.assertEqual(got, {
            ("A_REQ", False, True), ("B_NOFB", False, False), ("C_FB", True, False),
            ("D_NOFB", False, False), ("E_FB", True, False), ("F_NONE", False, False),
            ("G_REQ", False, True), ("H_FB", True, False)})

    def test_writes_comments_and_wsgi_environ_are_ignored(self):
        got, _ = reads('''
os.environ["SET_ME"] = "1"
# os.environ["COMMENTED"]
x = request.environ["WSGI_KEY"]
if os.environ["CMP"] == "a": pass
''', "python")
        self.assertEqual({n for n, *_ in got}, {"CMP"})

    def test_dynamic_reads_are_counted(self):
        got, dynamic = reads('os.environ[name]\nos.getenv(var)\nos.environ.get(key, "x")\nos.getenv("OK")', "python")
        self.assertEqual(dynamic, 3)
        self.assertEqual({n for n, *_ in got}, {"OK"})


class NodeReaderTests(unittest.TestCase):
    def test_reads(self):
        got, _ = reads('''
const a = process.env.A_NOFB;
const b = process.env.B_FB || "x";
const c = process.env["C_NOFB"];
const d = process.env.D_FB ?? 5;
const e = import.meta.env.VITE_E;
const f = import.meta.env.MODE;
const { G_NOFB, H_FB = "1", I_ALIAS: renamed } = process.env;
const j = Deno.env.get("J_NOFB");
process.env.WRITTEN = "1";
if (process.env.K === "a") {}
''', "node")
        self.assertEqual(got, {
            ("A_NOFB", False, False), ("B_FB", True, False), ("C_NOFB", False, False),
            ("D_FB", True, False), ("VITE_E", False, False), ("G_NOFB", False, False),
            ("H_FB", True, False), ("I_ALIAS", False, False), ("J_NOFB", False, False),
            ("K", False, False)})

    def test_multiline_destructuring(self):
        got, _ = reads("const {\n  A,\n  B = 'x',\n} = process.env\n", "node")
        self.assertEqual(got, {("A", False, False), ("B", True, False)})

    def test_line_numbers(self):
        found, _ = ea.read_source("x.js", "\n\nconst a = process.env.A;\n", "node")
        self.assertEqual(found[0][1], 3)


class OtherLanguageTests(unittest.TestCase):
    def test_go(self):
        got, dynamic = reads('a := os.Getenv("A_GO")\nb, ok := os.LookupEnv("B_GO")\nc := os.Getenv(name)\n', "go")
        self.assertEqual(got, {("A_GO", False, False), ("B_GO", True, False)})
        self.assertEqual(dynamic, 1)

    def test_ruby(self):
        got, _ = reads('''
a = ENV["A_RB"]
b = ENV["B_RB"] || "x"
c = ENV.fetch("C_RB")
d = ENV.fetch("D_RB", "x")
e = ENV.fetch("E_RB") { "x" }
ENV["F_RB"] = "set"
g = ENV.key?("G_RB")
''', "ruby")
        self.assertEqual(got, {
            ("A_RB", False, False), ("B_RB", True, False), ("C_RB", False, True), ("D_RB", True, False),
            ("E_RB", True, False), ("G_RB", True, False)})

    def test_java_and_kotlin(self):
        got, _ = reads('''
String a = System.getenv("A_JV");
val b = System.getenv("B_KT") ?: "x"
String c = System.getenv().getOrDefault("C_JV", "x");
@Value("${D_SPRING}") String d;
@Value("${E_SPRING:fallback}") String e;
''', "java")
        self.assertEqual(got, {("A_JV", False, False), ("B_KT", True, False), ("C_JV", True, False),
                               ("D_SPRING", False, False), ("E_SPRING", True, False)})

    def test_php(self):
        got, _ = reads('''<?php
$a = getenv('A_PHP');
$b = getenv('B_PHP') ?: 'x';
$c = $_ENV['C_PHP'];
$d = $_ENV['D_PHP'] ?? 'x';
$e = env('E_PHP');
$f = env('F_PHP', 'x');
''', "php")
        self.assertEqual(got, {("A_PHP", False, False), ("B_PHP", True, False), ("C_PHP", False, False),
                               ("D_PHP", True, False), ("E_PHP", False, False), ("F_PHP", True, False)})

    def test_rust(self):
        got, _ = reads('let a = std::env::var("A_RS").unwrap();\nlet b = env::var("B_RS").unwrap_or("x".into());', "rust")
        self.assertEqual(got, {("A_RS", False, False), ("B_RS", True, False)})


class DotenvParsingTests(unittest.TestCase):
    def test_parse(self):
        rows = ea.parse_dotenv('# header\nA=1\nexport B="two words" # note\nC=\n# D=optional\nnot a line\n')
        self.assertEqual(rows, [("A", 2, "1", False), ("B", 3, "two words", False), ("C", 4, "", False),
                                ("D", 5, "optional", True)])

    def test_env_blocks_mapping_and_list(self):
        text = ("services:\n  web:\n    environment:\n      A: one\n      B: ${B}\n    ports:\n      - '80:80'\n"
                "  db:\n    environment:\n      - C=1\n      - D\n    env_file:\n      - .env\n      - ./other.env\n"
                "  worker:\n    env_file: .env.worker\n")
        self.assertEqual([(n, l) for n, l, _ in ea.env_blocks(text, "environment")],
                         [("A", 4), ("B", 5), ("C", 10), ("D", 11)])
        self.assertEqual([n for n, _l, _ in ea.env_blocks(text, "env_file")], [".env", "./other.env", ".env.worker"])

    def test_compose_vars(self):
        self.assertEqual(ea.compose_vars("image: x:${TAG:-latest}\n# ${COMMENT}\nA: ${B}\n"), [("TAG", 1), ("B", 3)])

    def test_names(self):
        for name in (".env.example", ".env.sample", ".env.template", "backend.env.example", "example.env"):
            self.assertTrue(ea.is_example_file(name), name)
        for name in (".env", ".env.local", "env.py", "docker-compose.yml"):
            self.assertFalse(ea.is_example_file(name), name)
        self.assertTrue(ea.is_real_env(".env.production"))
        self.assertFalse(ea.is_real_env(".env.example"))
        self.assertTrue(ea.is_compose("docker-compose.override.yml"))
        self.assertTrue(ea.is_compose("compose.yaml"))
        self.assertFalse(ea.is_compose("mycompose.yml"))


class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def rules(self, **kwargs):
        return [(f["rule"], f["variable"]) for f in ea.audit(self.root, **kwargs)["findings"]]

    def test_used_but_undocumented_and_required_vs_fallback(self):
        write(self.root, "app.py", 'a = os.environ["REQUIRED_VAR"]\nb = os.getenv("OPTIONAL_VAR", "x")\nc = os.getenv("DOCUMENTED")\n')
        write(self.root, ".env.example", "DOCUMENTED=\n")
        report = ea.audit(self.root)
        self.assertEqual([(f["rule"], f["variable"], f["severity"]) for f in report["findings"]],
                         [("ED001", "REQUIRED_VAR", "medium"), ("ED001", "OPTIONAL_VAR", "low")])
        self.assertTrue(report["variables"]["REQUIRED_VAR"]["required"])
        self.assertTrue(report["variables"]["OPTIONAL_VAR"]["has_fallback"])

    def test_documented_but_unused(self):
        write(self.root, "app.py", 'os.getenv("USED")\n')
        write(self.root, ".env.example", "USED=\nSTALE_ONE=1\n")
        self.assertEqual(self.rules(), [("ED002", "STALE_ONE")])

    def test_compose_and_ci_count_as_consumers_and_providers(self):
        write(self.root, "app.py", 'os.getenv("FROM_COMPOSE")\nos.getenv("FROM_CI")\n')
        write(self.root, ".env.example", "POSTGRES_PASSWORD=changeme\nVIA_ENV_FILE=\nCI_ONLY=\n")
        write(self.root, "docker-compose.yml", "services:\n  db:\n    image: postgres:16\n    environment:\n"
                                               "      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}\n      FROM_COMPOSE: a\n"
                                               "    env_file: .env.example\n")
        write(self.root, ".github/workflows/ci.yml", "jobs:\n  t:\n    runs-on: x\n    env:\n      FROM_CI: '1'\n      CI_ONLY: a\n")
        report = ea.audit(self.root)
        self.assertEqual([(f["rule"], f["variable"], f["severity"]) for f in report["findings"]],
                         [("ED001", "FROM_COMPOSE", "low"), ("ED001", "FROM_CI", "low")])
        self.assertTrue(report["variables"]["FROM_CI"]["in_ci"])
        self.assertTrue(report["variables"]["POSTGRES_PASSWORD"]["in_compose"])

    def test_duplicate_keys(self):
        write(self.root, ".env.example", "A=1\nB=2\nA=3\n# A=commented\n")
        write(self.root, "app.py", 'os.getenv("A"); os.getenv("B")\n')
        report = ea.audit(self.root)
        self.assertEqual([(f["rule"], f["line"]) for f in report["findings"]], [("ED003", 3)])
        self.assertIn("first on line 1", report["findings"][0]["message"])

    def test_secret_name_with_real_value_in_example(self):
        write(self.root, ".env.example", "\n".join([
            "SESSION_SECRET=" + REAL_VALUE, "API_TOKEN=changeme", "DB_PASSWORD=", "STRIPE_SECRET=<your key>",
            "JWT_SECRET=${JWT_SECRET}", "TOKEN_TTL=3600", "PUBLIC_API_KEY=" + REAL_VALUE, "PASSWORD_MIN=12",
            "# OLD_SECRET=" + REAL_VALUE, ""]))
        write(self.root, "app.py", "\n".join('os.getenv("%s")' % n for n in (
            "SESSION_SECRET", "API_TOKEN", "DB_PASSWORD", "STRIPE_SECRET", "JWT_SECRET", "TOKEN_TTL",
            "PUBLIC_API_KEY", "PASSWORD_MIN", "OLD_SECRET")))
        report = ea.audit(self.root)
        self.assertEqual([(f["rule"], f["variable"], f["severity"]) for f in report["findings"]],
                         [("ED004", "SESSION_SECRET", "high")])
        self.assertNotIn(REAL_VALUE, json.dumps(report))
        self.assertIn("Zq8L****p9", report["findings"][0]["message"])

    def test_client_prefixed_secret(self):
        write(self.root, "src/a.ts", "const k = import.meta.env.VITE_ADMIN_SECRET;\nconst m = import.meta.env.VITE_MAP_KEY;\n")
        write(self.root, ".env.example", "NEXT_PUBLIC_DB_PASSWORD=\nNEXT_PUBLIC_SITE_NAME=\nVITE_ADMIN_SECRET=\nVITE_MAP_KEY=\n")
        report = ea.audit(self.root)
        self.assertEqual(sorted(f["variable"] for f in report["findings"] if f["rule"] == "ED005"),
                         ["NEXT_PUBLIC_DB_PASSWORD", "VITE_ADMIN_SECRET"])
        self.assertTrue(all(f["severity"] == "high" for f in report["findings"] if f["rule"] == "ED005"))

    def test_no_example_file(self):
        write(self.root, "app.py", 'os.environ["A"]\n')
        report = ea.audit(self.root)
        self.assertEqual([f["rule"] for f in report["findings"]], ["ED009"])
        self.assertEqual(ea.suggest(report), "# A: read in app.py:1 (required)\nA=")

    def test_system_variables_are_skipped_unless_asked(self):
        write(self.root, "app.py", 'os.getenv("HOME")\nos.getenv("GITHUB_SHA")\nos.getenv("NODE_ENV")\nos.getenv("MINE")\n')
        write(self.root, ".env.example", "MINE=\n")
        self.assertEqual(self.rules(), [])
        self.assertEqual(sorted(v for _r, v in self.rules(include_system=True)), ["GITHUB_SHA", "HOME", "NODE_ENV"])

    def test_skips_dependency_dirs_and_excluded_globs(self):
        write(self.root, "node_modules/x/index.js", "process.env.IN_MODULES\n")
        write(self.root, "tests/t.py", 'os.getenv("IN_TESTS")\n')
        write(self.root, "app.py", 'os.getenv("MINE")\n')
        write(self.root, ".env.example", "MINE=\n")
        self.assertEqual(self.rules(), [("ED001", "IN_TESTS")])
        self.assertEqual(self.rules(exclude=("tests/*",)), [])

    def test_commented_out_example_keys_are_documented(self):
        write(self.root, "app.py", 'os.getenv("OPTIONAL_THING", "x")\n')
        write(self.root, ".env.example", "# OPTIONAL_THING=value\n")
        self.assertEqual(self.rules(), [])


class RealEnvTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        write(self.root, "app.py", 'os.environ["DATABASE_URL"]\nos.environ["API_KEY"]\nos.environ["PRESENT"]\nos.getenv("OPT", "x")\n')
        write(self.root, ".env.example", "DATABASE_URL=\nAPI_KEY=\nPRESENT=\nOPT=\n")
        write(self.root, ".env", "PRESENT=" + REAL_VALUE + "\nAPI_KEY=\nEXTRA_KEY=" + REAL_VALUE + "\nPRESENT=again\n")

    def test_reports_names_only_never_values(self):
        report = ea.audit(self.root)
        got = [(f["rule"], f["variable"]) for f in report["findings"]]
        self.assertEqual(sorted(got), [("ED003", "PRESENT"), ("ED006", "DATABASE_URL"), ("ED007", "API_KEY"),
                                       ("ED008", "EXTRA_KEY")])
        self.assertEqual(report["real_env"][".env"], {"keys": ["API_KEY", "EXTRA_KEY", "PRESENT"], "empty": ["API_KEY"]})
        self.assertNotIn(REAL_VALUE, json.dumps(report))
        self.assertNotIn("again", json.dumps(report))
        out = io.StringIO()
        with redirect_stdout(out):
            ea.main([str(self.root), "--table", "--fail-on", "never"])
        self.assertNotIn(REAL_VALUE, out.getvalue())

    def test_real_env_only_at_project_root(self):
        write(self.root, "sub/.env", "SOMETHING=" + REAL_VALUE + "\n")
        self.assertEqual(sorted(ea.audit(self.root)["real_env"]), [".env"])

    def test_empty_real_env_file(self):
        write(self.root, ".env", "")
        got = [f["rule"] for f in ea.audit(self.root)["findings"]]
        self.assertEqual(got.count("ED006"), 3)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = ea.main([str(a) for a in argv])
        return code, out.getvalue(), err.getvalue()

    def test_clean_project(self):
        write(self.root, "app.py", 'os.getenv("A")\n')
        write(self.root, ".env.example", "A=\n")
        code, out, _ = self.run_cli(self.root)
        self.assertEqual(code, 0)
        self.assertIn("0 findings", out)

    def test_exit_codes_and_fail_on(self):
        write(self.root, "app.py", 'os.getenv("A")\n')
        write(self.root, ".env.example", "B=1\n")
        self.assertEqual(self.run_cli(self.root)[0], 0)
        self.assertEqual(self.run_cli(self.root, "--fail-on", "low")[0], 1)
        self.assertEqual(self.run_cli(self.root, "--fail-on", "never")[0], 0)
        write(self.root, ".env.example", "A=\nSESSION_SECRET=" + REAL_VALUE + "\n")
        self.assertEqual(self.run_cli(self.root)[0], 1)

    def test_json_and_text(self):
        write(self.root, "app.py", 'os.environ["A"]\nos.environ[name]\n')
        write(self.root, ".env.example", "OTHER=1\n")
        code, out, _ = self.run_cli(self.root, "--json")
        data = json.loads(out)
        self.assertEqual(data["tool"], "env_audit")
        self.assertEqual(data["dynamic_reads"], 1)
        for key in ("file", "line", "rule", "name", "severity", "message", "fix"):
            self.assertIn(key, data["findings"][0])
        code, out, _ = self.run_cli(self.root)
        self.assertIn("app.py:1  ED001  medium  A is read but not in the example file (required, no fallback)", out)
        self.assertIn("note: 1 dynamic env reads", out)

    def test_suggest(self):
        write(self.root, "app.py", 'os.environ["DB_PASSWORD"]\nos.getenv("PORT", "80")\nos.getenv("KNOWN")\n')
        write(self.root, ".env.example", "KNOWN=\n")
        code, out, _ = self.run_cli(self.root, "--suggest")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip().split("\n"), [
            "# DB_PASSWORD: read in app.py:1 (required)", "DB_PASSWORD=changeme",
            "# PORT: read in app.py:2 (optional, the code has a fallback)", "PORT="])

    def test_not_a_directory(self):
        code, _, err = self.run_cli(self.root / "nope")
        self.assertEqual(code, 2)
        self.assertIn("not a directory", err)


class IgnoreFileTests(unittest.TestCase):
    def test_shipcheck_ignore_globs_skip_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "app.py", 'os.getenv("MINE")\n')
            write(root, "tests/t.py", 'os.getenv("IN_TESTS")\n')
            write(root, "fixtures/x.js", "process.env.IN_FIXTURES\n")
            write(root, ".env.example", "MINE=\n")
            write(root, ".shipcheck-ignore", "# fixtures\ntests/\nfixtures/**\nfp:abcdef012345\nrule:SC012:*.py\n")
            self.assertEqual([f["variable"] for f in ea.audit(root)["findings"]], [])
            self.assertEqual(ea.load_ignore(root), ["tests/", "fixtures/**"])


if __name__ == "__main__":
    unittest.main()
