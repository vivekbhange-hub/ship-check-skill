# shipcheck-ci

Run against the demo workspace built by `python examples/regenerate.py --materialize`.

```
$ python skills/shipcheck-ci/ci_audit.py .shipcheck-demo
```

```text
shipcheck ci: 1 workflow, 12 findings (5 high, 4 medium, 3 low, 0 info)
.github/workflows/deploy.yml:7  CI003  medium  no permissions: block at workflow level, and job(s) without one: deploy
    fix: Add `permissions: contents: read` at the top and grant extra scopes per job only where needed.
.github/workflows/deploy.yml:7  CI011  medium  deploy workflow has no concurrency: group (job(s): deploy)
    fix: Add `concurrency: { group: deploy-${{ github.ref }}, cancel-in-progress: false }` to the deploy workflow or job.
.github/workflows/deploy.yml:8  CI007  low     job deploy has no timeout-minutes (default is 360)
    fix: Add `timeout-minutes:` to the job, a bit above its normal duration.
.github/workflows/deploy.yml:9  CI010  high    job deploy runs on a self-hosted runner and the workflow triggers on pull_request_target
    fix: Use GitHub-hosted runners for pull_request triggers, or restrict runs to trusted contributors with required approval and ephemeral runners.
.github/workflows/deploy.yml:11  CI001  low     uses: actions/checkout@v4 (first-party) is pinned to a tag, not a commit SHA
    fix: Pin to the full 40-character commit SHA and keep the version in a comment: uses: owner/repo@<sha>  # v4.1.0
.github/workflows/deploy.yml:13  CI002  high    actions/checkout with ref: ${{ github.event.pull_request.head.sha }} under pull_request_target
    fix: Use pull_request for untrusted code. If you need pull_request_target, never check out or run the head; label-gate it and treat the PR as data only.
.github/workflows/deploy.yml:14  CI001  high    uses: acme-corp/deploy-action@main (third-party) is pinned to a branch, not a commit SHA
    fix: Pin to the full 40-character commit SHA and keep the version in a comment: uses: owner/repo@<sha>  # v4.1.0
.github/workflows/deploy.yml:18  CI008  low     job deploy installs dependencies without a cache
    fix: Use the setup action's built-in cache (cache: npm / pip / gradle ...) or actions/cache keyed on the lockfile.
.github/workflows/deploy.yml:21  CI009  medium  step 'Tests' sets continue-on-error: true
    fix: Remove continue-on-error from test and lint steps, or quarantine the flaky test properly.
.github/workflows/deploy.yml:24  CI004  high    untrusted value interpolated into a script: ${{ github.event.pull_request.title }}
    fix: Pass the value through env and quote it in the script: env: TITLE: ${{ github.event.pull_request.title }} then "$TITLE".
.github/workflows/deploy.yml:25  CI005  high    secret printed with echo/printf: ${{ secrets.DEPLOY_TOKEN }}
    fix: Pass the secret as an environment variable (env: TOKEN: ${{ secrets.TOKEN }}) or to the action's with: input, and never echo it.
.github/workflows/deploy.yml:26  CI006  medium  downloads a script and pipes it into a shell
    fix: Download to a file, verify a checksum or signature, then run it; or use a pinned action or package.
```

Exit code: 1
