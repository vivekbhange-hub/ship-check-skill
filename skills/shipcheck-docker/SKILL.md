---
name: shipcheck-docker
description: >-
  Lints a Dockerfile and its .dockerignore for the footguns that hurt in production (floating
  base tags, running as root, curl piped to a shell, secrets in ENV or ARG, cache-busting COPY
  order, apt layers left dirty, shell-form CMD that swallows signals) and then rewrites it as a
  multi-stage, non-root, cache-friendly build that behaves the same. Use when the user says
  "lint my Dockerfile", "review this Dockerfile", "make my Docker image smaller", "why is my
  Docker build slow", "is this Dockerfile secure", or "harden my container".
argument-hint: "[Dockerfile or folder, default .]"
---

# shipcheck-docker: lint it, then rewrite it without changing what it does

The lint is mechanical and cheap; the value is in the rewrite. The rule of the rewrite: the
container must start the same process, with the same ports, environment and files, only
safer and faster to rebuild.

## Inputs

- A Dockerfile (or a folder to search). The `.dockerignore` next to it is read too.
- Commands below say `python3`; on Windows use `python` (or `py -3`).
- Permission to edit the Dockerfile and `.dockerignore`. Never run `docker build` or push an
  image unless the user asks.

## Outputs

- Findings DL001 to DL020 with severity, line and a fix.
- A rewritten Dockerfile and `.dockerignore`, plus a short list of what changed and why, and
  anything about behaviour you could not verify without building.

## Steps

1. **Lint.**
   ```
   python3 "${CLAUDE_SKILL_DIR}/dockerfile_lint.py" . --fail-on never
   ```
   Multi-stage aware: layer rules (apt, pip cache) apply only to stages that end up in the final
   image; USER and CMD rules look at the final stage.

2. **Understand the behaviour before touching it.** Read the whole file and write down: base
   image and version, build steps, the final CMD or ENTRYPOINT, exposed ports, environment, the
   user, working directory, files that must exist at run time. This is your equivalence checklist.

3. **Fix the high findings first** (they block a release): DL005 curl piped to a shell
   (download, verify checksum, run), DL010 secrets in ENV or ARG (remove; use
   `RUN --mount=type=secret` at build time and runtime variables at run time), DL020 secret
   files copied in.

4. **Rewrite to this shape** unless the project has a reason not to:
   - Stage 1 `builder`: full toolchain, copy only dependency manifests, install from the
     lockfile, then copy the source and build.
   - Final stage: a small pinned base, `COPY --from=builder` of the built output only,
     `USER` set to a non-root account, `HEALTHCHECK` if the app has an endpoint, exec-form CMD.
   - One RUN for `apt-get update && apt-get install -y --no-install-recommends ... && rm -rf
     /var/lib/apt/lists/*`.
   - Pin the base by tag (and by digest if the user maintains bumps). Look the current tag up
     from the user's registry or docs; do not invent a version.

5. **Write `.dockerignore`** with at least `.git`, `.env`, `node_modules`, build output and
   editor folders, so the context is small and cannot carry secrets.

6. **Re-lint** and confirm only advisories remain. Then walk the equivalence checklist from step
   2 and state each item as unchanged or changed (with the reason). If Docker is available and
   the user agrees, suggest `docker build` and a smoke test, and report the result honestly.

## Decision rules

- Non-root with a file-permission failure at run time: `chown` the needed directories to the app
  user in the builder stage via `COPY --chown`, not `chmod 777`.
- Port below 1024 on a non-root user: change the app port (and EXPOSE) or add
  `NET_BIND_SERVICE`; tell the user, because it changes the contract.
- The image needs a shell script entrypoint: keep it, make it `exec "$@"` at the end so signals work.
- Alpine versus slim: musl breaks some wheels and native modules; prefer `-slim` unless the
  project already uses Alpine.
- A base image that is a stage name or `scratch` is never flagged for tags.
- `DL011` (HEALTHCHECK) is an advisory: skip it when Kubernetes or Compose defines probes.

## What NOT to do

- Do not change the runtime behaviour silently: ports, env var names, working directory, entry
  command and user-visible paths stay the same unless you say so and the user agrees.
- Do not invent image tags, digests or checksums. Ask the user, or tell them how to look them up.
- Do not put secrets into the Dockerfile as a "temporary" step; build secrets are not secret in layers.
- Do not run `docker build`, `docker push` or `docker system prune` without being asked, and do
  not touch images or registries the user is not authorized to use.
