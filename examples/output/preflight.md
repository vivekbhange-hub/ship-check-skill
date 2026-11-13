# shipcheck-preflight

Run against the demo workspace built by `python examples/regenerate.py --materialize`.

```
$ python skills/shipcheck-preflight/preflight.py .shipcheck-demo
```

```text
# Pre-flight report

Verdict: NO-GO. 16 blocker(s) are open; do not ship until each is fixed or explicitly accepted by the owner.

| Check | High | Medium | Low | Info | Status |
|---|---:|---:|---:|---:|---|
| secrets | 7 | 3 | 0 | 0 | ran |
| env | 2 | 7 | 5 | 0 | ran |
| docker | 2 | 7 | 7 | 1 | ran |
| ci | 5 | 4 | 3 | 0 | ran |

## Blockers (16)

- [ci] `.github/workflows/deploy.yml:9` CI010: job deploy runs on a self-hosted runner and the workflow triggers on pull_request_target
  - Fix: Use GitHub-hosted runners for pull_request triggers, or restrict runs to trusted contributors with required approval and ephemeral runners.
- [ci] `.github/workflows/deploy.yml:13` CI002: actions/checkout with ref: ${{ github.event.pull_request.head.sha }} under pull_request_target
  - Fix: Use pull_request for untrusted code. If you need pull_request_target, never check out or run the head; label-gate it and treat the PR as data only.
- [ci] `.github/workflows/deploy.yml:14` CI001: uses: acme-corp/deploy-action@main (third-party) is pinned to a branch, not a commit SHA
  - Fix: Pin to the full 40-character commit SHA and keep the version in a comment: uses: owner/repo@<sha>  # v4.1.0
- [ci] `.github/workflows/deploy.yml:24` CI004: untrusted value interpolated into a script: ${{ github.event.pull_request.title }}
  - Fix: Pass the value through env and quote it in the script: env: TITLE: ${{ github.event.pull_request.title }} then "$TITLE".
- [ci] `.github/workflows/deploy.yml:25` CI005: secret printed with echo/printf: ${{ secrets.DEPLOY_TOKEN }}
  - Fix: Pass the secret as an environment variable (env: TOKEN: ${{ secrets.TOKEN }}) or to the action's with: input, and never echo it.
- [docker] `Dockerfile:3` DL010: ENV JWT_SECRET sets a secret-looking value in the image: supe****23
  - Fix: Never bake secrets into the image: use `RUN --mount=type=secret` for build time and runtime environment variables for run time.
- [docker] `Dockerfile:9` DL005: downloads a script and pipes it straight into a shell
  - Fix: Download to a file, verify its checksum or signature, then run it.
- [env] `.env.example:5` ED004: SESSION_SECRET has a real-looking value in the example file: corr****le
  - Fix: Replace the value with a placeholder such as changeme, and rotate it if it was real.
- [env] `src/client.js:2` ED005: VITE_ADMIN_SECRET will be exposed to browsers by its prefix
  - Fix: Variables with this prefix are bundled into browser code. Keep secrets server-side under an unprefixed name.
- [secrets] `.env:1` SC011: database-url-password: Tr0u****xQ
  - Fix: Change the database password, then read the URL from the environment.
- [secrets] `.env:4` SC006: stripe-live-secret-key: sk_l****dc
  - Fix: Rotate or revoke it first, then load it from an environment variable or secret manager.
- [secrets] `config/settings.py:2` SC001: aws-access-key-id: AKIA****3H
  - Fix: Rotate or revoke it first, then load it from an environment variable or secret manager.
- [secrets] `config/settings.py:3` SC002: aws-secret-access-key: k3Jv****2q
  - Fix: Rotate or revoke it first, then load it from an environment variable or secret manager.
- [secrets] `config/settings.py:4` SC005: slack-webhook: http****4l
  - Fix: Regenerate the webhook in Slack, then store the URL as a secret.
- [secrets] `deploy/id_rsa:1` SC009: private-key-block: [private key block]
  - Fix: Treat the key as burned: generate a new pair, replace the public half everywhere.
- [secrets] `scripts/notify.sh:2` SC003: github-token: ghp_****R8
  - Fix: Rotate or revoke it first, then load it from an environment variable or secret manager.

## Should fix (21)

- [ci] `.github/workflows/deploy.yml:7` CI003: no permissions: block at workflow level, and job(s) without one: deploy
  - Fix: Add `permissions: contents: read` at the top and grant extra scopes per job only where needed.
- [ci] `.github/workflows/deploy.yml:7` CI011: deploy workflow has no concurrency: group (job(s): deploy)
  - Fix: Add `concurrency: { group: deploy-${{ github.ref }}, cancel-in-progress: false }` to the deploy workflow or job.
- [ci] `.github/workflows/deploy.yml:21` CI009: step 'Tests' sets continue-on-error: true
  - Fix: Remove continue-on-error from test and lint steps, or quarantine the flaky test properly.
- [ci] `.github/workflows/deploy.yml:26` CI006: downloads a script and pipes it into a shell
  - Fix: Download to a file, verify a checksum or signature, then run it; or use a pinned action or package.
- [docker] `Dockerfile` DL013: no .dockerignore: the whole folder, including .git and .env, is sent as build context
  - Fix: Add a .dockerignore next to the Dockerfile so the build context stays small and clean.
- [docker] `Dockerfile:1` DL001: base image node:latest uses the latest tag
  - Fix: Pin a specific version tag, for example node:20.11-alpine3.19.
- [docker] `Dockerfile:1` DL003: the final image runs as root: no USER instruction
  - Fix: Create a user and add `USER app` (or a numeric uid) before CMD in the final stage.
- [docker] `Dockerfile:4` DL010: ARG NPM_TOKEN is a build argument for a secret; build args are visible in `docker history`
  - Fix: Never bake secrets into the image: use `RUN --mount=type=secret` for build time and runtime environment variables for run time.
- [docker] `Dockerfile:7` DL008: apt-get update in its own RUN layer; the cached layer will go stale
  - Fix: Run `apt-get update && apt-get install ...` in a single RUN so the cache cannot go stale.
- [docker] `Dockerfile:12` DL016: chmod 777 makes files writable by every user
  - Fix: Grant the narrowest mode that works, for example 755 for directories or 644 for files, or chown to the runtime user.
- [docker] `Dockerfile:13` DL012: EXPOSE 22: this image is set up to accept SSH
  - Fix: Do not run sshd in a container; use `docker exec` or the platform's shell access.
- [env] `.env` ED006: SENTRY_DSN is required by src/worker.py:5 but is not set in .env
  - Fix: Add the key to your real .env, or give the code a fallback.
- [env] `.env` ED006: SMTP_HOST is required by src/server.js:5 but is not set in .env
  - Fix: Add the key to your real .env, or give the code a fallback.
- [env] `.env` ED006: VITE_ADMIN_SECRET is required by src/client.js:2 but is not set in .env
  - Fix: Add the key to your real .env, or give the code a fallback.
- [env] `.env` ED006: VITE_API_URL is required by src/client.js:1 but is not set in .env
  - Fix: Add the key to your real .env, or give the code a fallback.
- [env] `.env` ED007: JWT_SECRET is empty in .env but the code needs a value
  - Fix: Set a value for the key in your real .env.
- [env] `.env.example:8` ED003: PORT is defined twice in this example file (first on line 2)
  - Fix: Keep one definition; with dotenv the last one silently wins.
- [env] `src/worker.py:5` ED001: SENTRY_DSN is read but not in the example file (required, no fallback)
  - Fix: Add the variable to .env.example with a safe placeholder and a comment.
- [secrets] `.env` SC021: env-file-not-gitignored: [file]
  - Fix: Add the file name to .gitignore before the first `git add .`.
- [secrets] `.env.example:5` SC012: generic-secret-assignment: corr****le
  - Fix: If it is real, rotate it and read it from the environment; if not, add a placeholder or allowlist it.
- [secrets] `Dockerfile:3` SC012: generic-secret-assignment: supe****23
  - Fix: If it is real, rotate it and read it from the environment; if not, add a placeholder or allowlist it.

## Advisories (16)

- [ci] `.github/workflows/deploy.yml:8` CI007: job deploy has no timeout-minutes (default is 360)
- [ci] `.github/workflows/deploy.yml:11` CI001: uses: actions/checkout@v4 (first-party) is pinned to a tag, not a commit SHA
- [ci] `.github/workflows/deploy.yml:18` CI008: job deploy installs dependencies without a cache
- [docker] `Dockerfile:6` DL009: COPY of the whole context (line 6) comes before the dependency install on line 10
- [docker] `Dockerfile:8` DL006: apt-get install without --no-install-recommends
- [docker] `Dockerfile:8` DL007: apt package lists are left in the layer
- [docker] `Dockerfile:8` DL015: sudo in a RUN instruction
- [docker] `Dockerfile:10` DL018: npm install may rewrite the lockfile; npm ci installs exactly what it records and fails on drift
- [docker] `Dockerfile:11` DL004: ADD ./start.sh copies a local file; COPY says what you mean
- [docker] `Dockerfile:14` DL019: CMD is in shell form, so the process runs under /bin/sh -c and may miss SIGTERM
- [env] `.env` ED008: INTERNAL_FEATURE_X is set in .env but not in the example file
- [env] `.env.example:5` ED002: SESSION_SECRET is documented but no code reads it
- [env] `.env.example:7` ED002: LEGACY_FLAG is documented but no code reads it
- [env] `src/server.js:5` ED001: SMTP_PORT is read but not in the example file (has a fallback)
- [env] `src/worker.py:3` ED001: DEBUG is read but not in the example file (has a fallback)
- [docker] `Dockerfile:1` DL011: no HEALTHCHECK in the final image

## Not checked

Nothing was skipped.
```

Exit code: 1
