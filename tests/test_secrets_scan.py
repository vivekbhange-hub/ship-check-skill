"""Tests for skills/shipcheck-secrets/secrets_scan.py.

Every fake credential is assembled at runtime from fragments so that no complete token in a
real provider format is committed to this repository.
"""
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from _load import load, write

ss = load("shipcheck-secrets", "secrets_scan")

AWS_ID = "AKIA" + "QX7M2KD9RT4VBN3H"
AWS_SECRET = "k3Jv9sQ2mXw8Lp5T" + "zR7bN4cY6hG1dF0a" + "E+uVxW2q"
GH_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8" + "i9J0k1L2m3N4o5P6q7R8"
SLACK_TOKEN = "xox" + "b-" + "123456789012-" + "abcdefghijklmnop"
SLACK_HOOK = "https://hooks.slack.com/services/" + "T0123ABCD/B0456EFGH/" + "Qw3rTy7uIo9pAs5dFg2hJk4l"
STRIPE_LIVE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
STRIPE_TEST = "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc"
GOOGLE_KEY = "AIza" + "Rt7Kq2Lm" * 4 + "Zp3"
JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJ" + "zdWIiOiJ0ZXN0LXVzZXItNDIifQ" + "." + "x7Qm2LkR9vTnB4cY"
PEM_HEAD = "-----BEGIN RSA PRIV" + "ATE KEY-----"
PEM_BODY = "MIIEowIBAAKCAQEA" + "x7Qm2LkR9vTnB4cY"
DB_PASSWORD = "Tr0ub4dor" + "9xQ"
DB_URL = "postgres://app:" + DB_PASSWORD + "@db.prod.internal:5432/app"
ENTROPY_VALUE = "Zx9" + "Qv3Lm7Kp2Rt8Wn4Yb6Hd1"


def scan_text(text: str, name: str = "app.env"):
    return ss.scan_lines(name, enumerate(text.split("\n"), 1))


def rules(findings):
    return [f["rule"] for f in findings]


class MaskTests(unittest.TestCase):
    def test_mask_long_and_short(self):
        self.assertEqual(ss.mask(AWS_ID), "AKIA****3H")
        self.assertEqual(ss.mask("short"), "****")
        self.assertEqual(ss.mask("exactly12chr"), "exac****hr")
        self.assertEqual(ss.mask("elevenchars"), "****")

    def test_fingerprint_is_stable_and_rule_specific(self):
        a = ss.fingerprint("SC001", AWS_ID)
        self.assertEqual(a, ss.fingerprint("SC001", AWS_ID))
        self.assertNotEqual(a, ss.fingerprint("SC012", AWS_ID))
        self.assertRegex(a, r"^[0-9a-f]{12}$")

    def test_entropy(self):
        self.assertAlmostEqual(ss.entropy("aaaa"), 0.0)
        self.assertGreater(ss.entropy(ENTROPY_VALUE), 4.0)


class ProviderRuleTests(unittest.TestCase):
    CASES = [
        ("SC001", "key = '" + AWS_ID + "'", AWS_ID),
        ("SC002", "aws_secret_access_key = " + AWS_SECRET, AWS_SECRET),
        ("SC003", "GITHUB_TOKEN=" + GH_TOKEN, GH_TOKEN),
        ("SC003", "x = 'github_pat_" + "11ABCDEFG0abcdefghij_" + "0123456789abcdefghijklmnop'",
         "github_pat_" + "11ABCDEFG0abcdefghij_" + "0123456789abcdefghijklmnop"),
        ("SC004", "SLACK=" + SLACK_TOKEN, SLACK_TOKEN),
        ("SC005", "url: " + SLACK_HOOK, SLACK_HOOK),
        ("SC006", "STRIPE=" + STRIPE_LIVE, STRIPE_LIVE),
        ("SC007", "STRIPE=" + STRIPE_TEST, STRIPE_TEST),
        ("SC008", "key: " + GOOGLE_KEY, GOOGLE_KEY),
        ("SC010", "Authorization: Bearer " + JWT, JWT),
    ]

    def test_each_rule_fires_once_and_is_masked(self):
        for rule, line, secret in self.CASES:
            with self.subTest(rule=rule):
                found = scan_text(line)
                self.assertEqual([f for f in found if f["rule"] == rule][0]["rule"], rule)
                self.assertEqual(len(found), 1, found)
                self.assertNotIn(secret, json.dumps(found))
                self.assertIn("****", found[0]["masked"])
                self.assertEqual(found[0]["line"], 1)

    def test_severities(self):
        sev = {rule: scan_text(line)[0]["severity"] for rule, line, _ in self.CASES}
        self.assertEqual(sev["SC001"], "high")
        self.assertEqual(sev["SC007"], "low")
        self.assertEqual(sev["SC008"], "medium")
        self.assertEqual(sev["SC010"], "medium")

    def test_private_key_needs_a_body(self):
        found = scan_text("\n".join(["x", PEM_HEAD, PEM_BODY, "-----END RSA PRIV" + "ATE KEY-----"]), "k.pem")
        self.assertEqual(rules(found), ["SC009"])
        self.assertEqual(found[0]["line"], 2)
        self.assertEqual(found[0]["masked"], "[private key block]")
        self.assertNotIn(PEM_BODY, json.dumps(found))
        # a header quoted in documentation or a regex is not a key
        self.assertEqual(scan_text("the header looks like " + PEM_HEAD + " and then prose"), [])

    def test_database_url(self):
        found = scan_text("DATABASE_URL=" + DB_URL, "x.env")
        self.assertEqual(rules(found), ["SC011"])
        self.assertEqual(found[0]["severity"], "high")
        self.assertNotIn(DB_PASSWORD, json.dumps(found))
        local = scan_text("DATABASE_URL=postgres://app:" + DB_PASSWORD + "@localhost:5432/app")
        self.assertEqual(local[0]["severity"], "low")
        self.assertIn("local development host", local[0]["message"])

    def test_database_url_placeholders_are_skipped(self):
        for pw in ("${DB_PASSWORD}", "$DB_PASSWORD", "{password}", "%s", "<password>", "changeme", "password"):
            with self.subTest(pw=pw):
                self.assertEqual(scan_text("u = 'postgres://app:" + pw + "@db.prod.internal/app'", "a.py"), [])

    def test_documented_examples_are_skipped(self):
        self.assertEqual(scan_text("k = 'AKIA" + "IOSFODNN7EXAMPLE'"), [])
        self.assertEqual(scan_text("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"), [])

    def test_two_secrets_on_one_line(self):
        found = scan_text("a=" + AWS_ID + " b=" + GH_TOKEN)
        self.assertEqual(sorted(rules(found)), ["SC001", "SC003"])


class GenericRuleTests(unittest.TestCase):
    def test_assignments_in_config_files(self):
        for line in ("DB_PASSWORD=hunter2hunter2", "api_key: 'k8Zq1WmPxR'", 'secret = "Winter2024!"',
                     '"client_secret": "pQ4rT9vXz2"', "export AUTH_TOKEN=abcd1234efgh"):
            with self.subTest(line=line):
                found = scan_text(line, "settings.env")
                self.assertEqual(rules(found), ["SC012"], found)
                self.assertEqual(found[0]["severity"], "medium")

    def test_value_is_never_in_output(self):
        found = scan_text("DB_PASSWORD=hunter2hunter2")
        self.assertNotIn("hunter2hunter2", json.dumps(found))
        self.assertEqual(found[0]["masked"], "hunt****r2")

    def test_placeholders_and_references_are_skipped(self):
        skipped = [
            "PASSWORD=", "PASSWORD=changeme", "API_KEY=your-api-key", "TOKEN=xxxxxxxx", "SECRET=<token>",
            "SECRET=${SECRET}", "TOKEN=$TOKEN", "PASSWORD={{ vault_password }}", "API_KEY=<your key here>",
            "password: 'placeholder-value'", "SECRET=replace_me_please", "TOKEN=********",
            "PASSWORD=%(db_password)s", "DB_PASSWORD=${DB_PASSWORD:-}", "token: dummy-token-value",
            "client_secret=INSERT_HERE", "SECRET_KEY=example-secret-key",
        ]
        for line in skipped:
            with self.subTest(line=line):
                self.assertEqual(scan_text(line, "x.env"), [])

    def test_source_code_references_are_skipped(self):
        skipped = [
            'password = os.environ["DB_PASSWORD"]', "const token = process.env.API_TOKEN;",
            'secret = settings.SECRET_KEY', 'token = request.headers["X"]', "password = get_password()",
            "api_key = config.api_key", 'token = "authorization-code"', "password: str = field()",
            'PASSWORD_MIN_LENGTH = 12', 'token_type = "bearer-token-type"', 'password == "hunter22hunter"',
            'pwd = "/home/runner/work"', 'secret_name = "my-db-secret-name"',
        ]
        for line in skipped:
            with self.subTest(line=line):
                self.assertEqual(scan_text(line, "app.py"), [])

    def test_bare_values_only_count_in_config_files(self):
        self.assertEqual(scan_text("password = hunter2hunter2", "app.py"), [])
        self.assertEqual(rules(scan_text("password = hunter2hunter2", "app.ini")), ["SC012"])
        self.assertEqual(rules(scan_text('password = "hunter2hunter2"', "app.py")), ["SC012"])

    def test_inline_ignore_comment(self):
        self.assertEqual(scan_text("DB_PASSWORD=hunter2hunter2  # shipcheck:ignore"), [])


class EntropyTests(unittest.TestCase):
    def test_flags_random_looking_value(self):
        found = scan_text("SESSION_SIGNING=" + ENTROPY_VALUE)
        self.assertEqual(rules(found), ["SC013"])
        self.assertNotIn(ENTROPY_VALUE, json.dumps(found))

    def test_skips_low_entropy_and_known_non_secrets(self):
        for line in (
            "NAME=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
            "image_tag=build20240101abcdefghijkl",
            "checksum=" + ENTROPY_VALUE,
            "commit_sha=" + ENTROPY_VALUE,
            "path=src/components/forms/validation42",
            "TITLE=thequickbrownfoxjumpsoverthelazydog",
            "uuid=123e4567-e89b-12d3-a456-426614174000",
            "x=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "hash=" + "0123456789abcdef" * 4,
        ):
            with self.subTest(line=line):
                self.assertEqual(scan_text(line), [])

    def test_hex_needs_length_and_entropy(self):
        self.assertEqual(rules(scan_text("SIGNING_THING=" + "9f86d081884c7d659a2feaa0c55ad015")), ["SC013"])
        self.assertEqual(scan_text("SIGNING_THING=" + "9f86d081884c7d65"), [])

    def test_long_lines_skip_generic_rules_but_not_provider_rules(self):
        line = "x=" + ENTROPY_VALUE + " " + "a" * 1200
        self.assertEqual(scan_text(line), [])
        self.assertEqual(rules(scan_text("a" * 1200 + " " + AWS_ID)), ["SC001"])


class AllowlistTests(unittest.TestCase):
    def test_parsing_and_matching(self):
        allow = ss.Allowlist("# comment\nfixtures/\n*.snap\ndocs/**\nfp:abcdef012345\n0123456789ab\n"
                             "rule:SC012:config/*.py\n")
        self.assertTrue(allow.path_ignored("fixtures/a/b.txt"))
        self.assertTrue(allow.path_ignored("src/x.snap"))
        self.assertTrue(allow.path_ignored("docs/deep/er/file.md"))
        self.assertFalse(allow.path_ignored("src/app.py"))
        self.assertEqual(allow.fingerprints, {"abcdef012345", "0123456789ab"})
        self.assertTrue(allow.finding_ignored({"fingerprint": "x", "rule": "SC012", "file": "config/a.py"}))
        self.assertFalse(allow.finding_ignored({"fingerprint": "x", "rule": "SC001", "file": "config/a.py"}))
        self.assertTrue(allow.finding_ignored({"fingerprint": "abcdef012345", "rule": "SC001", "file": "z"}))


class TreeScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_walk_scans_text_and_skips_the_rest(self):
        write(self.root, "src/settings.py", "KEY = '" + AWS_ID + "'\n")
        write(self.root, "node_modules/pkg/index.js", "KEY = '" + AWS_ID + "'\n")
        write(self.root, "vendor/lib.py", "KEY = '" + AWS_ID + "'\n")
        write(self.root, "package-lock.json", '{"integrity": "' + AWS_ID + '"}\n')
        write(self.root, "poetry.lock", AWS_ID + "\n")
        write(self.root, "build/out.js", "KEY = '" + AWS_ID + "'\n")
        (self.root / "logo.png").write_bytes(b"\x89PNG\r\n" + AWS_ID.encode())
        (self.root / "blob.dat").write_bytes(b"\x00\x01" + AWS_ID.encode())
        write(self.root, "big.txt", "k = " + AWS_ID + "\n" + "x" * 1_100_000)
        result = ss.scan(self.root)
        self.assertEqual([f["file"] for f in result["findings"]], ["src/settings.py"])
        self.assertFalse(result["git"])
        self.assertEqual(result["files_scanned"], 1)

    def test_shipcheck_ignore_file(self):
        write(self.root, "a/secret.py", "K = '" + AWS_ID + "'\n")
        write(self.root, "b/secret.py", "K = '" + GH_TOKEN + "'\n")
        write(self.root, "c/secret.py", "K = '" + STRIPE_LIVE + "'\n")
        fp = ss.fingerprint("SC006", STRIPE_LIVE)
        write(self.root, ".shipcheck-ignore", "a/\nfp:" + fp + "\n")
        result = ss.scan(self.root)
        self.assertEqual([f["file"] for f in result["findings"]], ["b/secret.py"])
        self.assertEqual(result["allowlisted"], 1)

    def test_single_file_path(self):
        write(self.root, "one.py", "K = '" + AWS_ID + "'\n")
        write(self.root, "two.py", "K = '" + GH_TOKEN + "'\n")
        result = ss.scan(self.root / "one.py")
        self.assertEqual([f["file"] for f in result["findings"]], ["one.py"])

    def test_crlf_files(self):
        (self.root / "w.ini").write_bytes(("A=1\r\nDB_PASSWORD=hunter2hunter2\r\n").encode())
        self.assertEqual([f["line"] for f in ss.scan(self.root)["findings"]], [2])

    def test_findings_are_sorted_and_deterministic(self):
        write(self.root, "z.py", "K = '" + AWS_ID + "'\n")
        write(self.root, "a.py", "K = '" + GH_TOKEN + "'\n")
        first = ss.scan(self.root)
        self.assertEqual([f["file"] for f in first["findings"]], ["a.py", "z.py"])
        self.assertEqual(json.dumps(first), json.dumps(ss.scan(self.root)))


class EnvHygieneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_env_name_detection(self):
        for name in (".env", ".env.local", ".env.production", "prod.env"):
            self.assertTrue(ss.is_env_file(name), name)
        for name in (".env.example", ".env.sample", ".env.template", "example.env", "app.py", ".envrc"):
            self.assertFalse(ss.is_env_file(name), name)

    def test_env_not_gitignored(self):
        write(self.root, ".env", "A=1\n")
        found = ss.scan(self.root)["findings"]
        self.assertEqual([(f["file"], f["rule"], f["severity"]) for f in found], [(".env", "SC021", "medium")])

    def test_env_gitignored(self):
        write(self.root, ".env", "A=1\n")
        write(self.root, ".gitignore", "# secrets\n.env\n")
        self.assertEqual(ss.scan(self.root)["findings"], [])

    def test_env_glob_in_gitignore(self):
        write(self.root, ".env.production", "A=1\n")
        write(self.root, ".gitignore", ".env*\n")
        self.assertEqual(ss.scan(self.root)["findings"], [])

    def test_example_without_gitignore_entry_is_advisory(self):
        write(self.root, ".env.example", "A=\n")
        found = ss.scan(self.root)["findings"]
        self.assertEqual([(f["rule"], f["severity"]) for f in found], [("SC022", "low")])
        write(self.root, ".gitignore", ".env\n")
        self.assertEqual(ss.scan(self.root)["findings"], [])


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class GitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.git("init", "-q")

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                        "-c", "commit.gpgsign=false", *args], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)

    def commit(self, message="c"):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def test_git_mode_skips_ignored_files(self):
        write(self.root, ".gitignore", "local.py\n")
        write(self.root, "local.py", "K = '" + AWS_ID + "'\n")
        write(self.root, "app.py", "K = '" + GH_TOKEN + "'\n")
        result = ss.scan(self.root)
        self.assertTrue(result["git"])
        self.assertEqual([f["file"] for f in result["findings"]], ["app.py"])
        self.assertEqual(ss.scan(self.root, use_git_files=False)["git"], False)

    def test_tracked_env_file_is_high(self):
        write(self.root, ".env", "A=1\n")
        self.commit()
        found = ss.scan(self.root)["findings"]
        self.assertEqual([(f["rule"], f["severity"]) for f in found], [("SC020", "high")])

    def test_ignored_env_file_is_fine(self):
        write(self.root, ".gitignore", ".env\n")
        write(self.root, ".env", "DB_PASSWORD=hunter2hunter2\n")
        self.commit()
        self.assertEqual(ss.scan(self.root)["findings"], [])

    def test_history_finds_a_deleted_secret(self):
        write(self.root, "app.py", "K = '" + AWS_ID + "'\n")
        self.commit("add key")
        write(self.root, "app.py", "K = os.environ['K']\n")
        self.commit("remove key")
        self.assertEqual(ss.scan(self.root)["findings"], [])
        found = ss.scan(self.root, history=10)["findings"]
        self.assertEqual([(f["file"], f["rule"]) for f in found], [("app.py", "SC001")])
        self.assertEqual(len(found[0]["commit"]), 7)
        self.assertNotIn(AWS_ID, json.dumps(found))
        self.assertIn("@" + found[0]["commit"], ss.location(found[0]))

    def test_history_respects_allowlist_and_count(self):
        write(self.root, "app.py", "K = '" + AWS_ID + "'\n")
        self.commit("add key")
        write(self.root, "app.py", "nothing\n")
        self.commit("remove key")
        write(self.root, "other.py", "x = 1\n")
        self.commit("later")
        self.assertEqual(ss.scan(self.root, history=1)["findings"], [])
        write(self.root, ".shipcheck-ignore", "fp:" + ss.fingerprint("SC001", AWS_ID) + "\n")
        self.assertEqual(ss.scan(self.root, history=10)["findings"], [])

    def test_ignored_subfolder_is_walked(self):
        write(self.root, ".gitignore", "demo/\n")
        write(self.root, "demo/app.py", "K = '" + AWS_ID + "'\n")
        result = ss.scan(self.root / "demo")
        self.assertFalse(result["git"])
        self.assertEqual([f["file"] for f in result["findings"]], ["app.py"])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = ss.main([str(a) for a in argv])
        return code, out.getvalue(), err.getvalue()

    def test_clean_tree_exits_zero(self):
        write(self.root, "a.py", "print('hi')\n")
        code, out, _ = self.run_cli(self.root)
        self.assertEqual(code, 0)
        self.assertIn("scanned 1 files, 0 findings", out)

    def test_text_output_is_masked_and_exit_one(self):
        write(self.root, "src/a.py", "K = '" + AWS_ID + "'\n")
        code, out, _ = self.run_cli(self.root)
        self.assertEqual(code, 1)
        self.assertNotIn(AWS_ID, out)
        self.assertIn("src/a.py:1  SC001  high    aws-access-key-id  AKIA****3H  fp:" + ss.fingerprint("SC001", AWS_ID), out)
        self.assertIn("rotate or revoke first", out)

    def test_fail_on_threshold(self):
        write(self.root, "a.env", "DB_PASSWORD=hunter2hunter2\n")
        self.assertEqual(self.run_cli(self.root)[0], 0)
        self.assertEqual(self.run_cli(self.root, "--fail-on", "medium")[0], 1)
        self.assertEqual(self.run_cli(self.root, "--fail-on", "never")[0], 0)
        write(self.root, "b.py", "K = '" + AWS_ID + "'\n")
        self.assertEqual(self.run_cli(self.root, "--fail-on", "never")[0], 0)
        self.assertEqual(self.run_cli(self.root)[0], 1)

    def test_json_output(self):
        write(self.root, "a.py", "K = '" + AWS_ID + "'\n")
        code, out, _ = self.run_cli(self.root, "--json")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(data["tool"], "secrets_scan")
        self.assertEqual(data["counts"], {"high": 1, "medium": 0, "low": 0, "info": 0})
        item = data["findings"][0]
        for key in ("file", "line", "rule", "name", "severity", "message", "fix", "masked", "fingerprint"):
            self.assertIn(key, item)
        self.assertNotIn(AWS_ID, out)

    def test_errors_exit_two(self):
        code, _, err = self.run_cli(self.root / "missing")
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)
        self.assertEqual(self.run_cli(self.root, "--history", "--history-commits", "0")[0], 2)

    def test_list_rules(self):
        code, out, _ = self.run_cli("--list-rules")
        self.assertEqual(code, 0)
        self.assertIn("SC001", out)
        self.assertIn("SC020", out)

    def test_no_complete_secret_in_any_rule_output(self):
        secrets = [AWS_ID, AWS_SECRET, GH_TOKEN, SLACK_TOKEN, SLACK_HOOK, STRIPE_LIVE, GOOGLE_KEY, JWT,
                   DB_PASSWORD, ENTROPY_VALUE, PEM_BODY]
        write(self.root, "all.env", "\n".join([
            "A=" + AWS_ID, "aws_secret_access_key=" + AWS_SECRET, "G=" + GH_TOKEN, "S=" + SLACK_TOKEN,
            "H=" + SLACK_HOOK, "ST=" + STRIPE_LIVE, "GK=" + GOOGLE_KEY, "J=" + JWT, "D=" + DB_URL,
            "SIGNING_THING=" + ENTROPY_VALUE, PEM_HEAD, PEM_BODY]) + "\n")
        for flags in ([], ["--json"]):
            _, out, _ = self.run_cli(self.root, *flags)
            for secret in secrets:
                self.assertNotIn(secret, out)
        self.assertGreaterEqual(len(ss.scan(self.root)["findings"]), 10)


class FalsePositiveGuardTests(unittest.TestCase):
    def test_regex_and_expression_values_in_code_are_not_passwords(self):
        for line in ('NOT_SECRET = re.compile(r"(?i)(public|path|file)")', 'TOKEN_RE = "^[A-Za-z0-9]+(?:-[a-z]+)*$"',
                     'SECRET_PATTERN = "(abc|def)ghijkl"'):
            with self.subTest(line=line):
                self.assertEqual(scan_text(line, "scanner.py"), [])

    def test_file_named_dockerfile_something_py_is_not_a_config_file(self):
        self.assertFalse(ss.is_config_file("skills/x/dockerfile_lint.py"))
        for name in ("Dockerfile", "Dockerfile.dev", "api.dockerfile", ".env.local", "settings.ini"):
            self.assertTrue(ss.is_config_file(name), name)


if __name__ == "__main__":
    unittest.main()
