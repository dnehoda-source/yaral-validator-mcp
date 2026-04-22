# YARA-L Validator CLI

A single-file CLI for validating only the rules that changed in a PR. Designed
to plug into CI (GitHub Actions, Cloud Build, Jenkins) but runs locally too.

## Install

Copy `validate_changed.py` into your rules repo, or fetch it at runtime:

```bash
curl -fsSL https://raw.githubusercontent.com/dnehoda-source/yaral-validator-mcp/master/cli/validate_changed.py \
  -o validate_changed.py
pip install requests
```

## Run locally

```bash
export VALIDATOR_URL=https://yaral-validator-xxxx.a.run.app
export VALIDATOR_ID_TOKEN=$(gcloud auth print-identity-token --audiences=$VALIDATOR_URL)

python validate_changed.py \
  --rules-dir rules \
  --base origin/main \
  --out results.json \
  --markdown results.md
```

Exit code is `0` if every changed rule passed, `1` if any failed or errored.

Composite rules (those referencing `$var.detection.*` or `rule_name = "..."`)
are handled by `--composite-mode`:

- `static` (default): calls `/api/composite-static-validate`, which validates
  each referenced base rule end-to-end and runs a structural check on the
  composite. Returns in minutes, not hours. Does NOT exercise Chronicle's
  cascade scheduler.
- `skip`: marks composites `SKIPPED_COMPOSITE` without validation (legacy).

For full composite coverage, combine the static check in CI with a nightly
`cascade_validate` job that tolerates the 1-24 hour wait.

## Run in GitHub Actions

See `.github/workflows/validate-rules.yml` for a ready-to-use template.
Configuration required in the rules repo:

- Repository secrets:
  - `GCP_WORKLOAD_IDENTITY_PROVIDER`
  - `GCP_SERVICE_ACCOUNT`
- Repository variables:
  - `VALIDATOR_URL`

The service account must be listed in `ALLOWED_EMAILS` on the validator
deployment.

## Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--rules-dir` | required | Directory containing `.yaral` files. |
| `--validator-url` | `$VALIDATOR_URL` | URL of a running validator. |
| `--id-token` | `$VALIDATOR_ID_TOKEN` | Google ID token with `aud=VALIDATOR_URL`. |
| `--base` | `origin/main` | Git ref to diff against. |
| `--all` | off | Validate every rule, not just changed ones. |
| `--poll-seconds` | 180 | Max seconds to poll for detection per rule. |
| `--out` | `results.json` | Structured output. |
| `--markdown` | (off) | Optional markdown matrix (used by the PR comment step). |
| `--composite-mode` | `static` | `static` calls the composite fast path; `skip` marks composites SKIPPED without validating. |
| `--validation-mode` | `udm_direct` | `udm_direct` (fast, parser bypassed), `parser_path` (raw logs through parser), `both` (gate on both). |
| `--log-type` | (empty) | Chronicle log type for `parser_path` / `both` (e.g. `WINEVTLOG`, `OKTA`, `GCP_CLOUDAUDIT`). |

## Output format

`results.json` is an array of `{path, rule_name, status, detail, validation_id, elapsed_s}`.
`status` is one of:

| Status | Meaning |
|--------|---------|
| `PASS` | Rule fired on synthetic events. |
| `FAIL` | Ingestion succeeded but no detection was observed in the poll window. |
| `ERROR` | Non-2xx from the validator or unexpected response. |
| `UNAUTHORIZED` | Token rejected. Check audience and `ALLOWED_EMAILS`. |
| `SKIPPED_COMPOSITE` | Composite rule detected; validate in a nightly job. |
| `UNKNOWN` | Server returned a status this CLI doesn't recognize (file a bug). |
