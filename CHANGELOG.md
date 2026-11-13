# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-13

### Added

- Five skills: `shipcheck-secrets`, `shipcheck-env`, `shipcheck-docker`, `shipcheck-ci` and
  `shipcheck-preflight`.
- Two read-only agents: `release-gatekeeper` and `secret-rotation-guide`.
- Helper scripts (standard library only): `secrets_scan.py` (provider patterns, entropy,
  allowlist, optional git history, always masked), `env_audit.py`, `dockerfile_lint.py`,
  `ci_audit.py` (with a hand-written YAML subset parser) and `preflight.py`.
- A deliberately flawed sample app under `examples/sample-app/`. Its fake credentials are
  assembled at run time by `examples/regenerate.py`, never committed; the masked outputs in
  `examples/output/` are checked byte-for-byte by the test suite.
- CI on Linux, Windows and macOS with Python 3.9, 3.12 and 3.13.
