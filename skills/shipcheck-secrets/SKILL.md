---
name: shipcheck-secrets
description: >-
  Scans a project, and optionally its recent git history, for leaked secrets (AWS, GitHub,
  Slack, Stripe and Google keys, private keys, JWTs, database URLs with passwords, generic
  password and token assignments, high-entropy strings) with masked output, then runs a
  rotation-first response: assume the secret is burned, revoke it first, clean history only
  afterwards and only if the user wants. Use when the user says "scan for secrets", "did I
  commit an API key", "check this before I push", "I pushed a token by accident", "is my .env
  safe", "rotate this key", or "find leaked credentials".
argument-hint: "[folder, default .]"
---

# shipcheck-secrets: find the leak, then rotate before anything else

A secret that reached a commit, a log or a chat is burned. Deleting the line does not un-leak
it: bots scrape public pushes within minutes, and every clone and fork keeps a copy. So this
skill finds the secret with `secrets_scan.py` (output always masked), and then puts rotation
ahead of cleanup.

## Inputs

- A project folder (default `.`). Git is used for the file list when the folder is a repo.
- Optional: how many commits of history to scan (`--history`, default 50 commits).
- Commands below say `python3`; on Windows use `python` (or `py -3`).

## Outputs

- A masked findings list: `file:line`, rule id, severity, name, `AKIA****3H`-style value and a
  fingerprint (`fp:...`) that is stable across runs and used for allowlisting.
- A rotation plan per provider, in order, and an optional history cleanup plan.
- Optional `.shipcheck-ignore` entries for confirmed false positives.

## Steps

1. **Confirm authorization.** Only scan a project the user owns or has permission to audit.
   Scanning someone else's repository for credentials is not what this skill is for.

2. **Scan.**
   ```
   python3 "${CLAUDE_SKILL_DIR}/secrets_scan.py" . --fail-on never
   python3 "${CLAUDE_SKILL_DIR}/secrets_scan.py" . --history --history-commits 200 --fail-on never
   ```
   Use `--json` when you need to process the result. The second form also lists secrets that
   were committed and later deleted: they are still in history, so they are still leaked.

3. **Read the result back by location, never by value.** Say "SC001 at `config/settings.py:2`",
   not the key. If the user pastes a real secret into the chat, stop and tell them it is now
   burned too (chat logs are not a secret store); continue with the masked form only.

4. **Triage each finding** with the user: real credential, test or fixture value, or false
   positive. SC012 and SC013 (generic and entropy) are the likeliest false positives; provider
   rules (SC001 to SC011) almost never are. SC020 and SC021 are about `.env` files, not values.

5. **Rotate first, for every real secret.** Order matters; do not skip ahead:
   1. Revoke or rotate it at the provider (table below). Create the new one first when the
      service would otherwise go down, then disable the old one.
   2. Put the new value where the code reads it from: an environment variable, the platform's
      secret store or CI secrets. Never back into a tracked file.
   3. Check the provider's audit log for use of the old secret since it was exposed.
   4. Only then remove it from the working tree and replace it with a placeholder.

6. **History cleanup (optional, after rotation).** Ask whether they want it; it is often not
   worth it once the secret is dead. If yes: `git filter-repo --replace-text` (or BFG), then a
   coordinated force-push with the team told first, and a request to the host to purge cached
   views. Say plainly that forks and clones keep the old commits.

7. **Stop it recurring.** A tracked env file: `git rm --cached .env`, add it to `.gitignore`
   (SC020, SC021, SC022). Add a pre-push hook or CI step running
   `python3 secrets_scan.py . --fail-on high`. Put confirmed false positives in
   `.shipcheck-ignore` as `fp:<fingerprint>` lines with a comment saying why.

## Rotation pointers

| Finding | Where to rotate | Also do |
|---|---|---|
| AWS key (SC001, SC002) | IAM > Users > Security credentials: create new key, deactivate then delete old | CloudTrail for the old key id; check for new users, roles, instances |
| GitHub token (SC003) | Settings > Developer settings > tokens: delete or regenerate | Review the audit log and recent pushes |
| Slack token or webhook (SC004, SC005) | Slack app settings: revoke token, remove and re-add the webhook | Check the app's recent activity |
| Stripe key (SC006, SC007) | Dashboard > Developers > API keys: roll the key | Review recent charges, webhooks, payouts |
| Google API key (SC008) | Cloud console > Credentials: regenerate, add API and referrer restrictions | Check quota and billing spikes |
| Private key (SC009) | Generate a new pair; remove the old public key from servers, deploy keys, CI | Check auth logs on every host that trusted it |
| JWT (SC010) | Revoke the session; rotate the signing secret if the token is long-lived | Expect all users to sign in again |
| Database URL (SC011) | Change the password in the database or cloud console | Review connections and recent writes |
| Generic or entropy (SC012, SC013) | Whatever system it belongs to; ask the user which | Same: logs, then replace |

## Decision rules

- Pushed to a remote, public or not: burned, rotate. Only in a local commit that was never
  shared: still rotate if it was ever pasted, synced or backed up elsewhere; otherwise cleaning
  the local history first is acceptable.
- A `sk_test_` style key (SC007) is low risk, but roll it when it is cheap to do so.
- Unsure what a secret unlocks: ask the blast-radius questions (what can it read, write, spend,
  delete?) or hand the masked findings to the `secret-rotation-guide` agent.
- A finding in a vendored or generated file: allowlist the path, do not edit the vendor file.
- No git repo: the scan walks the folder; say so, because ignored files are then scanned too.

## What NOT to do

- Do not print, quote, paste or log a secret value, in chat, files, commits or PR text. Mask
  it, or refer to rule id and location.
- Do not rewrite history before rotating, and never force-push without the user asking for it.
- Do not tell the user they are safe because the file was deleted or the repo is private.
- Do not allowlist with broad globs such as `**` or a whole source folder; use fingerprints.
- Do not scan or rotate credentials the user is not authorized to manage.
