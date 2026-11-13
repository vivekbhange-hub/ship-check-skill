# shipcheck-env --suggest

Run against the demo workspace built by `python examples/regenerate.py --materialize`.

```
$ python skills/shipcheck-env/env_audit.py .shipcheck-demo --suggest
```

```text
# DEBUG: read in src/worker.py:3 (optional, the code has a fallback)
DEBUG=
# SENTRY_DSN: read in src/worker.py:5 (required)
SENTRY_DSN=
# SMTP_PORT: read in src/server.js:5 (optional, the code has a fallback)
SMTP_PORT=
```

Exit code: 0
