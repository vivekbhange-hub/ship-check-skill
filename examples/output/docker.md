# shipcheck-docker

Run against the demo workspace built by `python examples/regenerate.py --materialize`.

```
$ python skills/shipcheck-docker/dockerfile_lint.py .shipcheck-demo
```

```text
shipcheck docker: 1 Dockerfile, 17 findings (2 high, 7 medium, 7 low, 1 info)
Dockerfile  DL013  medium  no .dockerignore: the whole folder, including .git and .env, is sent as build context
    fix: Add a .dockerignore next to the Dockerfile so the build context stays small and clean.
Dockerfile:1  DL001  medium  base image node:latest uses the latest tag
    fix: Pin a specific version tag, for example node:20.11-alpine3.19.
Dockerfile:1  DL003  medium  the final image runs as root: no USER instruction
    fix: Create a user and add `USER app` (or a numeric uid) before CMD in the final stage.
Dockerfile:1  DL011  info    no HEALTHCHECK in the final image
    fix: Add a HEALTHCHECK, or rely on the orchestrator's probes and say so.
Dockerfile:3  DL010  high    ENV JWT_SECRET sets a secret-looking value in the image: supe****23
    fix: Never bake secrets into the image: use `RUN --mount=type=secret` for build time and runtime environment variables for run time.
Dockerfile:4  DL010  medium  ARG NPM_TOKEN is a build argument for a secret; build args are visible in `docker history`
    fix: Never bake secrets into the image: use `RUN --mount=type=secret` for build time and runtime environment variables for run time.
Dockerfile:6  DL009  low     COPY of the whole context (line 6) comes before the dependency install on line 10
    fix: COPY only the manifest (package.json, requirements.txt, go.mod) and install first, then COPY the rest.
Dockerfile:7  DL008  medium  apt-get update in its own RUN layer; the cached layer will go stale
    fix: Run `apt-get update && apt-get install ...` in a single RUN so the cache cannot go stale.
Dockerfile:8  DL006  low     apt-get install without --no-install-recommends
    fix: Add --no-install-recommends to apt-get install.
Dockerfile:8  DL007  low     apt package lists are left in the layer
    fix: End the same RUN with `rm -rf /var/lib/apt/lists/*`.
Dockerfile:8  DL015  low     sudo in a RUN instruction
    fix: Remove sudo; build steps already run as root, and the final user should not need it.
Dockerfile:9  DL005  high    downloads a script and pipes it straight into a shell
    fix: Download to a file, verify its checksum or signature, then run it.
Dockerfile:10  DL018  low     npm install may rewrite the lockfile; npm ci installs exactly what it records and fails on drift
    fix: Install from a lockfile: `npm ci`, `yarn install --frozen-lockfile`, `pip install -r requirements.txt` with pinned versions.
Dockerfile:11  DL004  low     ADD ./start.sh copies a local file; COPY says what you mean
    fix: Use COPY for local files; for URLs use curl with a checksum, or ADD --checksum.
Dockerfile:12  DL016  medium  chmod 777 makes files writable by every user
    fix: Grant the narrowest mode that works, for example 755 for directories or 644 for files, or chown to the runtime user.
Dockerfile:13  DL012  medium  EXPOSE 22: this image is set up to accept SSH
    fix: Do not run sshd in a container; use `docker exec` or the platform's shell access.
Dockerfile:14  DL019  low     CMD is in shell form, so the process runs under /bin/sh -c and may miss SIGTERM
    fix: Use exec form, for example CMD ["node", "server.js"], so signals reach your process.
```

Exit code: 1
