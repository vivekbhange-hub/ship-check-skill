---
name: shipcheck-env
description: >-
  Finds environment variable drift: variables the code reads that nobody documented, documented
  ones nothing reads, reads with no fallback, duplicate keys, secrets with real-looking values
  in the example file and secret names that browser bundles would expose. Then writes or
  refreshes .env.example with safe placeholders and comments. Never prints a value from a real
  .env. Use when the user says "audit my env vars", "update .env.example", "what env vars does
  this app need", "it works on my machine but not in prod", "why is this variable undefined", or
  "document the environment variables".
argument-hint: "[project folder, default .]"
---

# shipcheck-env: make the environment the code needs match the one you documented

Most "works on my machine" deploys are env drift: a variable added to the code and never to
`.env.example`, a stale key nobody removed, a secret value pasted into the example file. This
skill compares what the code reads with what is documented, then fixes the documentation.

## Inputs

- A project folder (default `.`).
- Commands below say `python3`; on Windows use `python` (or `py -3`).
- Permission to edit `.env.example` (never a real `.env`).

## Outputs

- A findings list with rule ids ED001 to ED009, severity, file and line.
- An updated `.env.example` (or `.env.sample`, whichever the project already uses) where every
  variable the code reads appears once, with a comment and a placeholder.
- A short note on what the audit cannot see (dynamic reads, framework config files).

## Steps

1. **Run the audit.**
   ```
   python3 "${CLAUDE_SKILL_DIR}/env_audit.py" . --table --fail-on never
   ```
   It reads Python, Node (`process.env`, `import.meta.env`), Go, Ruby, Java/Kotlin, PHP and Rust
   sources, then the example files, docker-compose `environment:` and `env_file:`, and CI
   `env:` blocks. A real `.env` is reported by key name and emptiness only.

2. **Read the findings.** What each rule means:
   - ED001 used but undocumented. "required, no fallback" is the one that breaks a fresh
     deploy; "has a fallback" or "set in compose" is housekeeping.
   - ED002 documented but unused: stale, or consumed by something other than the code.
   - ED003 duplicate key: with dotenv the last definition silently wins.
   - ED004 a secret-named key with a real-looking value in the example file.
   - ED005 a secret behind a client prefix (`VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`...): browsers get it.
   - ED006 to ED008 compare the real `.env` with the code and the example, by name only.
   - ED009 there is no example file at all.

3. **Generate the additions** instead of typing them:
   ```
   python3 "${CLAUDE_SKILL_DIR}/env_audit.py" . --suggest
   ```
   Each line is `KEY=` or `KEY=changeme` for secret-like names, with a comment naming where it
   is read and whether it is required.

4. **Edit the example file.** Add missing keys under a heading that matches how the file is
   already grouped. For every key write a short comment (what it is, where to get it, format,
   required or optional and the default). Placeholders must be obviously fake: empty,
   `changeme`, `<your-api-key>` or `https://example.invalid`. Remove duplicates, keeping the
   definition with the better comment.

5. **Fix ED004 and ED005 in the code and the file, not only the report.** ED004: replace the
   value with a placeholder, and if it was real, treat it as leaked (see `shipcheck-secrets`).
   ED005: rename the variable without the client prefix and read it server-side; if the value
   is truly public, rename it so it no longer says secret.

6. **Re-run** the audit; the counts for ED001 to ED004 should be zero, then show the user a
   before and after summary.

## Decision rules

- Variables set by the platform (`PATH`, `HOME`, `CI`, `GITHUB_*`, `NODE_ENV`) are skipped by
  default; do not add them to the example file unless the user asks.
- A var read only in tests: document it in a `# tests only` section or leave it out, and say which.
- A real-looking value in the example file and a real `.env` with the same key name: do not
  compare them; say only that the key exists.
- Dynamic reads (`os.environ[name]`) are counted but cannot be audited; tell the user the count.
- Config loaded through a settings library (pydantic, dotenv schema, Spring `application.yml`)
  may read variables the scan cannot see; list those names from the config file by hand.

## What NOT to do

- Do not open, print, quote or paste values from a real `.env`, `.env.local` or `.env.production`.
  The script reports key names and emptiness only; keep it that way.
- Do not put real credentials, even test ones, into `.env.example`.
- Do not delete a documented variable just because the scan found no reader; ask first.
- Do not edit files outside the project, and do not write to a real env file without the user's
  explicit permission.
