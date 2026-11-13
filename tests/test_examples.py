"""The bundled demo: committed outputs must be exactly what the scripts produce (examples/regenerate.py)."""
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from _load import ROOT, load, load_path

regen = load_path(ROOT / "examples" / "regenerate.py", "regenerate_under_test")
ss = load("shipcheck-secrets", "secrets_scan")
OUTPUT = ROOT / "examples" / "output"
SAMPLE = ROOT / "examples" / "sample-app"
EXPECTED = ["ci.md", "docker.md", "env-suggest.md", "env.md", "preflight.md", "secrets.md"]


class DeterminismTests(unittest.TestCase):
    def test_regenerating_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            written = regen.generate(Path(tmp))
            self.assertEqual(written, EXPECTED)
            self.assertEqual(regen.compare(OUTPUT, Path(tmp)), [])

    def test_check_mode(self):
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(regen.main(["--check"]), 0)
        self.assertIn("up to date", out.getvalue())

    def test_compare_reports_differences(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            (Path(a) / "x.md").write_text("1", encoding="utf-8")
            (Path(b) / "x.md").write_text("2", encoding="utf-8")
            (Path(b) / "y.md").write_text("2", encoding="utf-8")
            self.assertEqual(regen.compare(Path(a), Path(b)), ["y.md: not committed", "x.md: content differs"])

    def test_outputs_use_lf(self):
        for name in EXPECTED:
            with self.subTest(file=name):
                self.assertNotIn(b"\r\n", (OUTPUT / name).read_bytes())


class SafetyTests(unittest.TestCase):
    def test_committed_tree_has_no_secret_files(self):
        names = {p.relative_to(SAMPLE).as_posix() for p in SAMPLE.rglob("*") if p.is_file()}
        self.assertEqual(names, {
            ".env.example", ".github/workflows/deploy.yml", "Dockerfile", "docker-compose.yml", "package.json",
            "src/client.js", "src/server.js", "src/worker.py"})

    def test_no_provider_format_secret_anywhere_in_the_repo(self):
        """The scanner itself is the check: provider-format rules (SC001-SC010) must find nothing."""
        result = ss.scan(ROOT, use_git_files=False, allow=ss.Allowlist(".shipcheck-demo/\n"))
        provider = [f for f in result["findings"] if f["rule"] <= "SC010" and f["rule"].startswith("SC0")]
        self.assertEqual(provider, [], [(f["file"], f["line"], f["rule"]) for f in provider])
        hygiene = [f for f in result["findings"] if f["rule"] in ("SC020", "SC021")]
        self.assertEqual([(f["file"], f["rule"]) for f in hygiene], [])

    def test_committed_outputs_carry_only_masked_values(self):
        for name in EXPECTED:
            text = (OUTPUT / name).read_text(encoding="utf-8")
            found = ss.scan_lines(name, enumerate(text.split("\n"), 1))
            self.assertEqual([f for f in found if f["rule"] in ("SC001", "SC002", "SC003", "SC004", "SC005",
                                                                  "SC006", "SC008", "SC009", "SC010", "SC011")], [], name)
        secrets_out = (OUTPUT / "secrets.md").read_text(encoding="utf-8")
        for masked in ("AKIA****3H", "ghp_****R8", "sk_l****dc", "[private key block]"):
            self.assertIn(masked, secrets_out)


class WorkspaceTests(unittest.TestCase):
    def test_materialize_adds_runtime_secrets_that_the_scanner_finds(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "demo"
            added = regen.materialize(target)
            self.assertEqual(added, [".env", "config/settings.py", "deploy/id_rsa", "scripts/notify.sh"])
            self.assertTrue((target / "Dockerfile").is_file())
            result = ss.scan(target, use_git_files=False)
            self.assertEqual(sorted({f["rule"] for f in result["findings"] if f["rule"] < "SC011"}),
                             ["SC001", "SC002", "SC003", "SC005", "SC006", "SC009"])
            self.assertEqual(sorted(f["file"] for f in result["findings"] if f["rule"] == "SC011"), [".env"])
            # rebuilding over a workspace this script made is fine
            regen.materialize(target)

    def test_materialize_refuses_to_delete_a_foreign_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "precious.txt").write_text("keep me", encoding="utf-8")
            with self.assertRaises(ValueError):
                regen.materialize(Path(tmp))
            self.assertTrue((Path(tmp) / "precious.txt").exists())

    def test_materialize_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "ws"
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(regen.main(["--materialize", str(target)]), 0)
            self.assertIn("fake credentials", out.getvalue())
            self.assertTrue((target / "config" / "settings.py").is_file())
            with redirect_stderr(io.StringIO()) as err:
                self.assertEqual(regen.main(["--materialize", str(ROOT)]), 2)
            self.assertIn("refusing", err.getvalue())

    def test_fake_values_are_not_whole_literals_in_the_generator(self):
        source = (ROOT / "examples" / "regenerate.py").read_text(encoding="utf-8")
        for literal in ("AKIA" + "QX7M2KD9RT4VBN3H", "ghp_a1B2", "sk_" + "live_", "-----BEGIN RSA PRIVATE" + " KEY-----"):
            self.assertNotIn(literal, source)


class DemoContentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = {name: (OUTPUT / name).read_text(encoding="utf-8") for name in EXPECTED}

    def test_secrets(self):
        text = self.out["secrets.md"]
        self.assertIn("shipcheck secrets: scanned 13 files, 10 findings (7 high, 3 medium, 0 low, 0 info)", text)
        for rule in ("SC001", "SC002", "SC003", "SC005", "SC006", "SC009", "SC011", "SC012", "SC021"):
            self.assertIn(rule, text)

    def test_env(self):
        text = self.out["env.md"]
        self.assertIn(".env.example:8  ED003  medium  PORT is defined twice in this example file (first on line 2)", text)
        self.assertIn("ED005  high    VITE_ADMIN_SECRET will be exposed to browsers by its prefix", text)
        self.assertIn("real env files (names only): .env", text)
        self.assertNotIn("postgres://", text)
        self.assertIn("SENTRY_DSN=", self.out["env-suggest.md"])

    def test_docker_and_ci(self):
        self.assertIn("17 findings (2 high, 7 medium, 7 low, 1 info)", self.out["docker.md"])
        self.assertIn("12 findings (5 high, 4 medium, 3 low, 0 info)", self.out["ci.md"])
        for rule in ("CI001", "CI002", "CI003", "CI004", "CI005", "CI006", "CI007", "CI008", "CI009", "CI010", "CI011"):
            self.assertIn(rule, self.out["ci.md"])

    def test_preflight_refuses_to_ship(self):
        text = self.out["preflight.md"]
        self.assertIn("Verdict: NO-GO. 16 blocker(s) are open", text)
        self.assertNotIn("ship it", text.lower())
        self.assertIn("## Blockers (16)", text)


if __name__ == "__main__":
    unittest.main()
