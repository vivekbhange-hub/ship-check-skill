# shipcheck-env

Run against the demo workspace built by `python examples/regenerate.py --materialize`.

```
$ python skills/shipcheck-env/env_audit.py .shipcheck-demo
```

```text
shipcheck env: 3 source files read 11 variables; examples: .env.example; compose: docker-compose.yml; ci: .github/workflows/deploy.yml; real env files (names only): .env
14 findings (2 high, 7 medium, 5 low, 0 info)
.env  ED006  medium  SENTRY_DSN is required by src/worker.py:5 but is not set in .env
.env  ED006  medium  SMTP_HOST is required by src/server.js:5 but is not set in .env
.env  ED006  medium  VITE_ADMIN_SECRET is required by src/client.js:2 but is not set in .env
.env  ED006  medium  VITE_API_URL is required by src/client.js:1 but is not set in .env
.env  ED007  medium  JWT_SECRET is empty in .env but the code needs a value
.env  ED008  low     INTERNAL_FEATURE_X is set in .env but not in the example file
.env.example:5  ED002  low     SESSION_SECRET is documented but no code reads it
.env.example:5  ED004  high    SESSION_SECRET has a real-looking value in the example file: corr****le
.env.example:7  ED002  low     LEGACY_FLAG is documented but no code reads it
.env.example:8  ED003  medium  PORT is defined twice in this example file (first on line 2)
src/client.js:2  ED005  high    VITE_ADMIN_SECRET will be exposed to browsers by its prefix
src/server.js:5  ED001  low     SMTP_PORT is read but not in the example file (has a fallback)
src/worker.py:3  ED001  low     DEBUG is read but not in the example file (has a fallback)
src/worker.py:5  ED001  medium  SENTRY_DSN is read but not in the example file (required, no fallback)
```

Exit code: 1
