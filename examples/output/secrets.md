# shipcheck-secrets

Run against the demo workspace built by `python examples/regenerate.py --materialize`.

```
$ python skills/shipcheck-secrets/secrets_scan.py .shipcheck-demo
```

```text
shipcheck secrets: scanned 13 files, 10 findings (7 high, 3 medium, 0 low, 0 info)
.env  SC021  medium  env-file-not-gitignored  [file]  fp:2a0d2d9716a1
.env:1  SC011  high    database-url-password  Tr0u****xQ  fp:cb9647389230
.env:4  SC006  high    stripe-live-secret-key  sk_l****dc  fp:90d27b22a891
.env.example:5  SC012  medium  generic-secret-assignment  corr****le  fp:3f2834d024a4
Dockerfile:3  SC012  medium  generic-secret-assignment  supe****23  fp:d6cd4fea2f27
config/settings.py:2  SC001  high    aws-access-key-id  AKIA****3H  fp:3dd4f60d538c
config/settings.py:3  SC002  high    aws-secret-access-key  k3Jv****2q  fp:d2fce5eea898
config/settings.py:4  SC005  high    slack-webhook  http****4l  fp:eefe331324e5
deploy/id_rsa:1  SC009  high    private-key-block  [private key block]  fp:36c4285fda0d
scripts/notify.sh:2  SC003  high    github-token  ghp_****R8  fp:7b12fb344b38
Treat every secret above as exposed: rotate or revoke first, clean history later.
```

Exit code: 1
