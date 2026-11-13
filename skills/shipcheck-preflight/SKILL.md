---
name: shipcheck-preflight
description: >-
  The 60-second pre-flight for anything about to ship: runs the secrets scan, the env audit, the
  Dockerfile lint and the CI audit in order, merges the findings into a one-page go or no-go
  report (blockers, should-fix, advisories) and refuses to say "ship it" while any high-severity
  finding is open. Use when the user says "pre-flight check", "am I ready to deploy", "check
  before I push", "run all the ship checks", "is this safe to release", or "go or no-go".
argument-hint: "[project folder, default .]"
---

# shipcheck-preflight: one report, one verdict

This skill orchestrates the other four. It does not invent findings or soften them: the
verdict is computed by `preflight.py` from the findings, and you report it as printed.

## Inputs

- A project folder (default `.`). Authorization to audit it: the user's own project or one
  they have permission to review.
- Commands below say `python3`; on Windows use `python` (or `py -3`).
- Optional: `--history` to include recent git history in the secrets scan.

## Outputs

- A Markdown report: verdict line, a table per check, then Blockers (high), Should fix
  (medium), Advisories (low and info) and a "Not checked" list.
- Optionally the report saved as `PREFLIGHT.md` if the user asks. Never commit it for them.

## Steps

1. **Run everything in order.**
   ```
   python3 "${CLAUDE_SKILL_DIR}/preflight.py" .
   ```
   It runs, in this order, `../shipcheck-secrets/secrets_scan.py`,
   `../shipcheck-env/env_audit.py`, `../shipcheck-docker/dockerfile_lint.py` and
   `../shipcheck-ci/ci_audit.py`, each with `--json`, and merges the results. For history too:
   `python3 "${CLAUDE_SKILL_DIR}/preflight.py" . --history`.

2. **Report the verdict exactly as printed**, one of:
   - `NO-GO`: at least one high finding is open.
   - `INCOMPLETE`: a check failed to run; nothing can be promised.
   - `GO WITH CONDITIONS`: no blockers, but medium findings remain.
   - `GO`: nothing at high or medium. This is the only verdict where you may say "ship it".

3. **Lead with the blockers.** For each: what it is, where, the fix, and for any secret, the
   rotation-first rule (see `shipcheck-secrets`). Group related items (one leaked key in three
   files is one problem). Mask every value.

4. **Hand off the fixes** to the specific skill: `shipcheck-secrets`, `shipcheck-env`,
   `shipcheck-docker`, `shipcheck-ci`. Offer to fix them one at a time; do not bundle edits
   across all four without asking.

5. **Re-run after fixes.** Show the verdict change. A blocker is closed only when the script no
   longer reports it, not when you believe it is fixed.

6. **For a go-or-no-go opinion on the report**, delegate to the `release-gatekeeper` agent; for
   the order of rotation steps, to `secret-rotation-guide`.

## Decision rules

- Any high finding open: the answer is no-go, however small the change or urgent the deploy.
  The user may accept a risk themselves; you do not declare it safe. If they do, record who
  accepted which finding in your reply and keep the verdict as printed.
- `INCOMPLETE` beats an optimistic reading: fix the failing check (path, Python version) first.
- "Not checked" items are part of the report: an unparseable workflow is not a clean workflow.
- Advisories never block. Do not promote or demote severities to get a better verdict.
- A check with no inputs (no Dockerfile, no workflows) is reported as not applicable, not as passed.

## What NOT to do

- Do not say "ship it", "safe to release" or "all clear" unless the verdict is `GO`.
- Do not hand-edit the verdict, drop findings, or mark a false positive without a
  `.shipcheck-ignore` entry the user has seen.
- Do not print secret values from any finding; the scripts mask them and you must too.
- Do not push, deploy, tag a release or change repository settings. This skill only reads and reports.
