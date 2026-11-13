"""Tests for skills/shipcheck-ci/ci_audit.py (YAML subset parser and the workflow rules)."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from _load import load, write

ca = load("shipcheck-ci", "ci_audit")
SHA = "0123456789abcdef" * 2 + "01234567"  # 40 hex characters, obviously not a real commit


def audit(text, name="ci.yml"):
    return ca.audit_workflow(name, ca.parse_yaml(text))


def rules(findings):
    return sorted(f["rule"] for f in findings)


def by_rule(findings, rule):
    return [f for f in findings if f["rule"] == rule]


SAFE = f"""name: ci
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@{SHA}  # v4.1.0
      - uses: actions/setup-node@{SHA}
        with:
          node-version: 20
          cache: npm
      - run: npm ci
      - run: npm test
"""


class YamlParserTests(unittest.TestCase):
    def test_nested_maps_and_sequences(self):
        data = ca.parse_yaml("""# top comment
name: CI   # trailing
on:
  push:
    branches: [main, 'release/*']
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run it
        run: echo "hi # not a comment"
        env:
          A: 1
          B: "two words"
""")
        self.assertEqual(data["name"], "CI")
        self.assertEqual(list(data["on"]["push"]["branches"]), ["main", "release/*"])
        steps = data["jobs"]["build"]["steps"]
        self.assertEqual(steps[0]["uses"], "actions/checkout@v4")
        self.assertEqual(steps[1]["run"], 'echo "hi # not a comment"')
        self.assertEqual(dict(steps[1]["env"]), {"A": "1", "B": "two words"})

    def test_line_numbers(self):
        data = ca.parse_yaml("a: 1\njobs:\n  x:\n    steps:\n      - run: one\n      - name: n\n        uses: u@v1\n")
        self.assertEqual(data.key_lines["a"], 1)
        self.assertEqual(data["jobs"].key_lines["x"], 3)
        steps = data["jobs"]["x"]["steps"]
        self.assertEqual(steps.item_lines, [5, 6])
        self.assertEqual(steps[1].key_lines["uses"], 7)

    def test_sequence_at_the_same_indent_as_its_key(self):
        data = ca.parse_yaml("branches:\n- main\n- dev\nother: 1\n")
        self.assertEqual(list(data["branches"]), ["main", "dev"])
        self.assertEqual(data["other"], "1")

    def test_literal_and_folded_blocks(self):
        data = ca.parse_yaml("run: |\n  line1\n    indented\n\n  line3\nnext: >-\n  folded one\n  folded two\nlast: x\n")
        self.assertEqual(data["run"], "line1\n  indented\n\nline3\n")
        self.assertEqual(data["run"].body_line, 2)
        self.assertTrue(data["run"].literal)
        self.assertEqual(data["next"], "folded one folded two")
        self.assertEqual(data["last"], "x")

    def test_block_scalar_chomping(self):
        data = ca.parse_yaml("a: |-\n  x\nb: |+\n  y\n\nc: |\n  z\n\n\nd: 1\n")
        self.assertEqual((data["a"], data["b"], data["c"]), ("x", "y\n\n", "z\n"))

    def test_block_scalar_in_a_sequence_item(self):
        data = ca.parse_yaml("steps:\n  - run: |\n      a\n      b\n    name: n\n  - |\n    raw\n")
        self.assertEqual(data["steps"][0]["run"], "a\nb\n")
        self.assertEqual(data["steps"][0]["name"], "n")
        self.assertEqual(data["steps"][1], "raw\n")

    def test_quoting(self):
        data = ca.parse_yaml("""a: 'it''s'
b: "tab\\tquote\\" done"
c: "# not a comment"
d: ${{ github.sha }}
"quoted key": v
e: "a: b"
""")
        self.assertEqual(data["a"], "it's")
        self.assertEqual(data["b"], 'tab\tquote" done')
        self.assertEqual(data["c"], "# not a comment")
        self.assertEqual(data["d"], "${{ github.sha }}")
        self.assertEqual(data["quoted key"], "v")
        self.assertEqual(data["e"], "a: b")

    def test_expressions_with_colons_and_hashes(self):
        data = ca.parse_yaml("if: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}\nx: a # comment\n")
        self.assertIn("github.ref == 'refs/heads/main'", data["if"])
        self.assertEqual(data["x"], "a")

    def test_flow_collections(self):
        data = ca.parse_yaml("a: [1, 2, {k: v}]\nb: {x: 1, y: [a, b]}\nc: []\nd: {}\nruns-on: [self-hosted, ${{ matrix.os }}]\n")
        self.assertEqual(data["a"][0], "1")
        self.assertEqual(data["a"][2]["k"], "v")
        self.assertEqual(list(data["b"]["y"]), ["a", "b"])
        self.assertEqual((list(data["c"]), dict(data["d"])), ([], {}))
        self.assertEqual(list(data["runs-on"]), ["self-hosted", "${{ matrix.os }}"])

    def test_document_start_and_crlf_and_bom(self):
        data = ca.parse_yaml("\ufeff---\r\nname: x\r\non: push\r\n")
        self.assertEqual((data["name"], data["on"]), ("x", "push"))

    def test_empty_values_and_documents(self):
        data = ca.parse_yaml("a:\nb: \nc:\n  d: 1\n")
        self.assertEqual((data["a"], data["b"], data["c"]["d"]), ("", "", "1"))
        self.assertEqual(ca.parse_yaml("# only a comment\n"), {})

    def test_matrix_include(self):
        data = ca.parse_yaml("strategy:\n  matrix:\n    os: [a, b]\n    include:\n      - os: c\n        extra: 1\n")
        self.assertEqual(data["strategy"]["matrix"]["include"][0]["extra"], "1")

    def test_unsupported_features_raise_with_line_numbers(self):
        cases = {
            "base: &anchor\n  a: 1\n": (1, "anchors"),
            "a: *alias\n": (1, "anchors"),
            "a: !!str 1\n": (1, "anchors"),
            "<<: *defaults\n": (1, "merge"),
            "a: 1\n---\nb: 2\n": (2, "multi-document"),
            "a: 'open\n": (1, "multi-line quoted"),
            "a: [1,\n  2]\n": (1, "multi-line flow"),
            "a: first\n  continued\n": (2, "multi-line plain"),
            "a: 1\na: 2\n": (2, "duplicate key"),
            "a:\n\tb: 1\n": (2, "tab"),
            "- - nested\n": (1, "nested sequences"),
            "a: 1\n  b: 2\n": (2, "multi-line plain"),
            "a: 1\n b\n": (2, "multi-line plain"),
            "? complex\n: key\n": (1, "complex keys"),
            "a: b: c\n": None,
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                if expected is None:
                    ca.parse_yaml(text)  # `a: b: c` parses as key a with plain value "b: c" in this subset
                    continue
                with self.assertRaises(ca.YamlSubsetError) as ctx:
                    ca.parse_yaml(text)
                self.assertEqual(ctx.exception.line, expected[0])
                self.assertIn(expected[1], ctx.exception.reason)


class PinningTests(unittest.TestCase):
    def uses(self, ref_line):
        return audit("on: push\npermissions: read-all\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n      - uses: " + ref_line + "\n")

    def test_severity_matrix(self):
        cases = {
            "actions/checkout@v4": "low", "actions/checkout@main": "medium", "github/codeql-action/init@v3": "low",
            "peaceiris/actions-gh-pages@v4": "medium", "peaceiris/actions-gh-pages@main": "high",
            "peaceiris/actions-gh-pages@v4.0.1": "medium", "owner/repo/sub/dir@release/v1": "high",
        }
        for ref, severity in cases.items():
            with self.subTest(ref=ref):
                found = by_rule(self.uses(ref), "CI001")
                self.assertEqual([f["severity"] for f in found], [severity])

    def test_pinned_and_local_are_fine(self):
        self.assertEqual(by_rule(self.uses("actions/checkout@" + SHA), "CI001"), [])
        self.assertEqual(by_rule(self.uses("./.github/actions/local"), "CI001"), [])
        self.assertEqual(by_rule(self.uses("docker://alpine@sha256:" + "a" * 64), "CI001"), [])
        self.assertEqual(by_rule(self.uses("docker://alpine:3.19"), "CI001")[0]["severity"], "low")

    def test_short_sha_is_not_pinned(self):
        self.assertEqual(len(by_rule(self.uses("actions/checkout@a1b2c3d"), "CI001")), 1)

    def test_no_ref_and_reusable_workflows(self):
        self.assertEqual(by_rule(self.uses("some/action"), "CI001")[0]["severity"], "high")
        found = audit("on: push\npermissions: read-all\njobs:\n  call:\n    uses: org/repo/.github/workflows/x.yml@main\n")
        self.assertEqual([(f["rule"], f["severity"], f["line"]) for f in found], [("CI001", "high", 5)])

    def test_line_number_points_at_uses(self):
        self.assertEqual(by_rule(self.uses("a/b@v1"), "CI001")[0]["line"], 8)


class PullRequestTargetTests(unittest.TestCase):
    def wf(self, with_block, trigger="pull_request_target"):
        return audit(f"on: {trigger}\npermissions: read-all\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n"
                     f"      - uses: actions/checkout@{SHA}\n{with_block}")

    def test_head_checkout_is_high(self):
        for ref in ("${{ github.event.pull_request.head.sha }}", "${{ github.event.pull_request.head.ref }}",
                    "refs/pull/${{ github.event.number }}/merge", "${{ github.head_ref }}"):
            with self.subTest(ref=ref):
                found = by_rule(self.wf(f"        with:\n          ref: {ref}\n"), "CI002")
                self.assertEqual([(f["severity"], f["line"]) for f in found], [("high", 10)])

    def test_head_repository_is_high(self):
        found = by_rule(self.wf("        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n"), "CI002")
        self.assertEqual(len(found), 1)

    def test_default_checkout_and_other_triggers_are_fine(self):
        self.assertEqual(by_rule(self.wf(""), "CI002"), [])
        self.assertEqual(by_rule(self.wf("        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n", "pull_request"), "CI002"), [])

    def test_run_step_checkout_of_head(self):
        text = ("on: pull_request_target\npermissions: read-all\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n"
                "      - run: git fetch origin ${{ github.event.pull_request.head.sha }} && git checkout FETCH_HEAD\n")
        self.assertEqual(len(by_rule(audit(text), "CI002")), 1)


class PermissionsTests(unittest.TestCase):
    JOB = "jobs:\n  j:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n      - run: echo\n"

    def test_missing_permissions(self):
        found = by_rule(audit("on: push\n" + self.JOB), "CI003")
        self.assertEqual([(f["severity"], f["line"]) for f in found], [("medium", 2)])

    def test_top_level_or_per_job_permissions_are_fine(self):
        self.assertEqual(by_rule(audit("on: push\npermissions:\n  contents: read\n" + self.JOB), "CI003"), [])
        self.assertEqual(by_rule(audit("on: push\npermissions: {}\n" + self.JOB), "CI003"), [])
        per_job = "on: push\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: 5\n    permissions:\n      contents: read\n    steps:\n      - run: echo\n"
        self.assertEqual(by_rule(audit(per_job), "CI003"), [])

    def test_write_all(self):
        top = by_rule(audit("on: push\npermissions: write-all\n" + self.JOB), "CI003")
        self.assertEqual([(f["severity"], f["line"]) for f in top], [("high", 2)])
        job = by_rule(audit("on: push\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: 5\n    permissions: write-all\n    steps:\n      - run: echo\n"), "CI003")
        self.assertEqual([f["severity"] for f in job], ["high"])


class InjectionTests(unittest.TestCase):
    def run_step(self, body):
        return audit("on: push\npermissions: read-all\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n      - name: s\n        run: |\n"
                     + "".join("          " + line + "\n" for line in body.split("\n")))

    def test_untrusted_contexts_are_high(self):
        for expr in ("github.event.issue.title", "github.event.pull_request.body", "github.head_ref",
                     "github.event.pull_request.head.ref", "github.event.comment.body",
                     "github.event.head_commit.message", "github.event.commits[0].message",
                     "github.event.pull_request.head.repo.default_branch", "github.event.workflow_run.head_branch",
                     "github.event.review.body", "github.event.pages[0].page_name"):
            with self.subTest(expr=expr):
                found = by_rule(self.run_step('echo "${{ ' + expr + ' }}"'), "CI004")
                self.assertEqual([f["severity"] for f in found], ["high"])

    def test_line_number_inside_literal_block(self):
        found = by_rule(self.run_step('echo ok\necho "${{ github.head_ref }}"'), "CI004")
        self.assertEqual([f["line"] for f in found], [11])

    def test_safe_contexts_are_not_flagged(self):
        for expr in ("github.sha", "github.repository", "github.event.pull_request.number", "github.run_id",
                     "secrets.TOKEN", "matrix.os", "github.ref_name", "env.X", "steps.a.outputs.b"):
            with self.subTest(expr=expr):
                self.assertEqual(by_rule(self.run_step('echo "${{ ' + expr + ' }}"'), "CI004"), [])

    def test_env_indirection_is_the_fix(self):
        text = ("on: push\npermissions: read-all\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n"
                "      - env:\n          TITLE: ${{ github.event.pull_request.title }}\n        run: echo \"$TITLE\"\n")
        self.assertEqual(by_rule(audit(text), "CI004"), [])

    def test_workflow_dispatch_inputs_are_medium(self):
        found = by_rule(self.run_step("echo ${{ inputs.target }}\necho ${{ github.event.inputs.env }}"), "CI004")
        self.assertEqual([f["severity"] for f in found], ["medium", "medium"])

    def test_github_script(self):
        text = ("on: push\npermissions: read-all\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n"
                f"      - uses: actions/github-script@{SHA}\n        with:\n          script: |\n"
                "            console.log('${{ github.event.issue.title }}')\n")
        self.assertEqual([f["line"] for f in by_rule(audit(text), "CI004")], [11])


class SecretsAndShellTests(unittest.TestCase):
    def wf(self, run, env=""):
        return audit("on: push\npermissions: read-all\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: 5\n" + env + "    steps:\n      - run: " + run + "\n")

    def test_echoed_secret_is_high(self):
        found = by_rule(self.wf('echo "${{ secrets.API_TOKEN }}"'), "CI005")
        self.assertEqual([f["severity"] for f in found], ["high"])
        self.assertIn("secrets.API_TOKEN", found[0]["message"])

    def test_secret_on_the_command_line_is_medium(self):
        found = by_rule(self.wf("./deploy.sh --token ${{ secrets.DEPLOY_TOKEN }}"), "CI005")
        self.assertEqual([f["severity"] for f in found], ["medium"])

    def test_env_var_from_secret_that_is_echoed(self):
        env = "    env:\n      TOKEN: ${{ secrets.TOKEN }}\n"
        self.assertEqual([f["severity"] for f in by_rule(self.wf('echo "$TOKEN"', env), "CI005")], ["high"])
        self.assertEqual(by_rule(self.wf("./deploy.sh", env), "CI005"), [])
        self.assertEqual(by_rule(self.wf('echo "${HOME}"', env), "CI005"), [])

    def test_password_stdin_is_accepted(self):
        self.assertEqual(by_rule(self.wf("echo ${{ secrets.P }} | docker login -u me --password-stdin"), "CI005"), [])

    def test_with_inputs_are_fine(self):
        text = (f"on: push\npermissions: read-all\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n"
                f"      - uses: some/action@{SHA}\n        with:\n          token: ${{{{ secrets.T }}}}\n")
        self.assertEqual(by_rule(audit(text), "CI005"), [])

    def test_pipe_to_shell(self):
        found = by_rule(self.wf("curl -fsSL https://x.example/install.sh | bash"), "CI006")
        self.assertEqual([f["severity"] for f in found], ["medium"])
        self.assertEqual(by_rule(self.wf("curl -fsSLo i.sh https://x.example/i.sh && sha256sum -c i.sum"), "CI006"), [])


class HygieneRuleTests(unittest.TestCase):
    def test_timeout(self):
        text = "on: push\npermissions: read-all\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo\n  b:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n      - run: echo\n"
        found = by_rule(audit(text), "CI007")
        self.assertEqual([(f["severity"], f["line"]) for f in found], [("low", 4)])

    def test_reusable_workflow_job_needs_no_timeout(self):
        found = audit(f"on: push\npermissions: read-all\njobs:\n  c:\n    uses: ./.github/workflows/x.yml\n")
        self.assertEqual(by_rule(found, "CI007"), [])

    def test_cache(self):
        base = "on: push\npermissions: read-all\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n"
        nocache = base + "      - uses: actions/setup-node@" + SHA + "\n      - run: npm ci\n"
        self.assertEqual([f["line"] for f in by_rule(audit(nocache), "CI008")], [9])
        with_cache = base + "      - uses: actions/setup-node@" + SHA + "\n        with:\n          cache: npm\n      - run: npm ci\n"
        self.assertEqual(by_rule(audit(with_cache), "CI008"), [])
        actions_cache = base + "      - uses: actions/cache@" + SHA + "\n      - run: pip install -r r.txt\n"
        self.assertEqual(by_rule(audit(actions_cache), "CI008"), [])
        no_install = base + "      - run: echo hi\n"
        self.assertEqual(by_rule(audit(no_install), "CI008"), [])
        for cmd in ("pip install x", "yarn install", "pnpm install", "bundle install", "poetry install", "go mod download"):
            self.assertEqual(len(by_rule(audit(base + "      - run: " + cmd + "\n"), "CI008")), 1, cmd)

    def test_continue_on_error(self):
        base = "on: push\npermissions: read-all\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n"
        for step in ("      - run: pytest\n        continue-on-error: true\n",
                     "      - name: Unit tests\n        run: ./go.sh\n        continue-on-error: true\n",
                     "      - run: npm run lint\n        continue-on-error: true\n"):
            self.assertEqual([f["severity"] for f in by_rule(audit(base + step), "CI009")], ["medium"], step)
        self.assertEqual(by_rule(audit(base + "      - run: ./notify.sh\n        continue-on-error: true\n"), "CI009"), [])
        self.assertEqual(by_rule(audit(base + "      - run: pytest\n        continue-on-error: false\n"), "CI009"), [])
        job = "on: push\npermissions: read-all\njobs:\n  tests:\n    continue-on-error: true\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n      - run: echo\n"
        self.assertEqual(len(by_rule(audit(job), "CI009")), 1)

    def test_self_hosted(self):
        def wf(runs_on, trigger):
            return audit(f"on: {trigger}\npermissions: read-all\njobs:\n  j:\n    runs-on: {runs_on}\n    timeout-minutes: 5\n    steps:\n      - run: echo\n")
        for runs_on in ("self-hosted", "[self-hosted, linux]", "{ group: ci-pool }"):
            self.assertEqual([f["severity"] for f in by_rule(wf(runs_on, "pull_request"), "CI010")], ["high"], runs_on)
        self.assertEqual(by_rule(wf("self-hosted", "push"), "CI010"), [])
        self.assertEqual(by_rule(wf("ubuntu-latest", "pull_request"), "CI010"), [])
        self.assertEqual(len(by_rule(wf("self-hosted", "[push, issue_comment]"), "CI010")), 1)

    def test_deploy_concurrency(self):
        job = "jobs:\n  deploy:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n      - run: echo\n"
        self.assertEqual(len(by_rule(audit("name: Deploy\non: push\npermissions: read-all\n" + job), "CI011")), 1)
        self.assertEqual(by_rule(audit("name: Deploy\non: push\npermissions: read-all\nconcurrency: deploy\n" + job), "CI011"), [])
        job_level = "jobs:\n  deploy:\n    runs-on: x\n    timeout-minutes: 5\n    concurrency: prod\n    steps:\n      - run: echo\n"
        self.assertEqual(by_rule(audit("name: x\non: push\npermissions: read-all\n" + job_level), "CI011"), [])
        self.assertEqual(len(by_rule(audit("name: x\non: push\npermissions: read-all\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n      - run: kubectl apply -f k.yml\n"), "CI011")), 1)
        self.assertEqual(by_rule(audit("name: tests\non: push\npermissions: read-all\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n      - run: echo\n", "tests.yml"), "CI011"), [])
        self.assertEqual(len(by_rule(audit("name: x\non: push\npermissions: read-all\n" + job, "deploy-prod.yml"), "CI011")), 1)

    def test_safe_workflow_has_no_findings(self):
        self.assertEqual(audit(SAFE), [])

    def test_trigger_forms(self):
        for trigger in ("push", "[push, pull_request_target]", "{ pull_request_target: { types: [opened] } }"):
            data = ca.parse_yaml("on: " + trigger + "\n")
            self.assertTrue(ca.triggers_of(data))
        self.assertEqual(ca.triggers_of(ca.parse_yaml("on:\n  push:\n  workflow_dispatch:\n")), {"push", "workflow_dispatch"})


class FilesAndCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = ca.main([str(a) for a in argv])
        return code, out.getvalue(), err.getvalue()

    def test_unparseable_file_is_reported_not_guessed(self):
        write(self.root, ".github/workflows/anchors.yml", "x: &a\n  y: 1\njobs:\n  j: *a\n")
        write(self.root, ".github/workflows/ok.yml", SAFE)
        result = ca.audit_files([self.root])
        self.assertEqual(result["workflows"], [".github/workflows/anchors.yml", ".github/workflows/ok.yml"])
        self.assertEqual(result["skipped"], [{"file": ".github/workflows/anchors.yml", "line": 1,
                                              "reason": "anchors, aliases and tags are not supported"}])
        self.assertEqual([(f["file"], f["rule"], f["severity"]) for f in result["findings"]],
                         [(".github/workflows/anchors.yml", "CI000", "info")])
        code, out, _ = self.run_cli(self.root)
        self.assertEqual(code, 0)
        self.assertIn("NOT audited", out)
        self.assertEqual(self.run_cli(self.root, "--fail-on", "info")[0], 1)

    def test_discovery(self):
        write(self.root, ".github/workflows/a.yml", SAFE)
        write(self.root, ".github/workflows/b.yaml", SAFE)
        write(self.root, ".github/workflows/readme.md", "x")
        write(self.root, "docker-compose.yml", "services: {}\n")
        self.assertEqual(ca.audit_files([self.root])["workflows"], [".github/workflows/a.yml", ".github/workflows/b.yaml"])
        self.assertEqual(ca.audit_files([self.root / ".github" / "workflows"])["workflows"], ["a.yml", "b.yaml"])
        self.assertEqual(len(ca.audit_files([self.root / ".github" / "workflows" / "a.yml"])["workflows"]), 1)

    def test_no_workflows(self):
        code, out, _ = self.run_cli(self.root)
        self.assertEqual(code, 0)
        self.assertIn("0 workflows, 0 findings", out)

    def test_exit_codes(self):
        write(self.root, ".github/workflows/bad.yml", "on: pull_request_target\npermissions: read-all\njobs:\n  j:\n    runs-on: self-hosted\n    timeout-minutes: 5\n    steps:\n      - run: echo\n")
        self.assertEqual(self.run_cli(self.root)[0], 1)
        self.assertEqual(self.run_cli(self.root, "--fail-on", "never")[0], 0)
        write(self.root, ".github/workflows/bad.yml", SAFE)
        self.assertEqual(self.run_cli(self.root, "--fail-on", "low")[0], 0)

    def test_text_and_explain(self):
        write(self.root, ".github/workflows/w.yml", "on: push\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n      - uses: a/b@v1\n")
        _, out, _ = self.run_cli(self.root, "--fail-on", "never")
        self.assertIn(".github/workflows/w.yml:7  CI001  medium  uses: a/b@v1 (third-party) is pinned to a tag, not a commit SHA", out)
        self.assertNotIn("why:", out)
        _, out, _ = self.run_cli(self.root, "--fail-on", "never", "--explain")
        self.assertIn("    why: A tag or branch can be moved", out)

    def test_json(self):
        write(self.root, ".github/workflows/w.yml", "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: echo\n")
        _, out, _ = self.run_cli(self.root, "--json", "--fail-on", "never")
        data = json.loads(out)
        self.assertEqual(data["tool"], "ci_audit")
        for key in ("file", "line", "rule", "name", "severity", "message", "fix", "why"):
            self.assertIn(key, data["findings"][0])

    def test_missing_path_and_list_rules(self):
        code, _, err = self.run_cli(self.root / "nope")
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)
        code, out, _ = self.run_cli("--list-rules")
        self.assertIn("CI011", out)


class IgnoreFileTests(unittest.TestCase):
    def test_shipcheck_ignore_globs_skip_workflows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, ".github/workflows/a.yml", SAFE)
            write(root, ".github/workflows/experimental.yml", "on: push\njobs:\n  j:\n    steps:\n      - uses: a/b@main\n")
            write(root, ".shipcheck-ignore", ".github/workflows/experimental.yml\n")
            self.assertEqual(ca.audit_files([root])["workflows"], [".github/workflows/a.yml"])


if __name__ == "__main__":
    unittest.main()
