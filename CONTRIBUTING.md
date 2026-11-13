# Contributing

Thanks for helping. This pack is small on purpose, so a few rules keep it that way.

## Ground rules

- Helper scripts use the Python standard library only, run on Python 3.9+, make no network
  calls, and produce the same bytes for the same input.
- Every script change comes with a test in `tests/`. Run the suite from the repo root:

  ```
  python -m unittest discover -s tests -v
  ```

- If your change alters what the demo produces, regenerate the committed outputs and include
  them in the same pull request:

  ```
  python examples/regenerate.py
  python examples/regenerate.py --check
  ```

- Write files with LF line endings (`.gitattributes` enforces this in git).
- Skills keep the frontmatter format checked by `tests/test_repo.py`: `name` equals the folder
  name, the description says what it does and lists trigger phrases, and the body has a
  "What NOT to do" section.

## Fixtures and secrets

This pack is about leaked credentials, so its own repository must never contain one.

- Build every fake credential at run time by joining fragments in test code, for example
  `"AKIA" + "QX7M2KD9RT4VBN3H"`. A complete token in a real provider format must not appear in
  any committed file, including docs and tests; GitHub push protection will (rightly) block it.
- The sample app under `examples/sample-app/` holds only obviously fake, non-provider values.
  Anything token-shaped is added by `examples/regenerate.py` into a temporary or git-ignored
  folder.
- `tests/test_examples.py` scans the whole repository with `secrets_scan.py` and fails on any
  provider-format match. Never silence it with an allowlist; fix the fixture.
- Output of every script stays masked: first 4 and last 2 characters at most, never a full value.

## Rules and heuristics

A new rule in any script needs a test where it fires, a test where a nearby safe case must not
fire, and a severity you can defend. Prefer a false negative with a clear note in the skill over
a noisy false positive: run `secrets_scan.py` on a few of your own projects before proposing a
secret pattern, and report how many findings were wrong.

`ci_audit.py` parses a YAML subset by hand. If you extend it, keep the rule that anything it
cannot parse is reported and skipped, never guessed.

## Conduct

Be kind and specific. This project follows the spirit of the
[Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Releasing

Bump `version` in `.claude-plugin/plugin.json` and add a matching `## [x.y.z] - YYYY-MM-DD`
section to `CHANGELOG.md`; the test suite checks that they agree.
