# YARA-L Detection Validator MCP Server

A detection engineering tool that proves YARA-L rules actually fire — and don't false-positive — by generating synthetic UDM events, ingesting them into Google SecOps, and verifying detections. No production data required.

## The Problem

Google SecOps ships test rule and retrohunt. Both are useful. Both require production data to run against.

That works in a live environment. It falls apart everywhere else:

- **SIEM migrations** — You're converting rules from a legacy SIEM into a SecOps tenant with no ingested logs. No data to retrohunt against. No way to know a converted rule will fire until real traffic starts flowing, which is also when it matters most.
- **Regression testing** — Every time you edit a shared detection library, you have no way to prove the rule you just touched still fires and still doesn't false-positive, short of waiting for production traffic.
- **Composite detections** — Rules that chain off other rules (`rule = "stage1_brute_force"` → `stage2_lateral_movement`) are especially brittle. One broken link kills the whole chain and nobody notices until an incident slips through. The tool validates these end-to-end, but because Chronicle evaluates composites on an HOURLY or DAILY schedule, expect to wait up to 1 hour (HOURLY) or 24 hours (DAILY) for the cascade to fire.
- **False positives** — A rule that fires on the happy path can still be over-broad. Proving it doesn't fire on near-miss traffic is a separate problem nobody currently solves programmatically.

A rule can be syntactically valid, pass a linter, and still never fire because a field mapping is wrong, a threshold is off by one, or a condition doesn't match how the data source actually formats events. There is no standard validation step in the detection lifecycle — rules are written and shipped with the assumption they work.

## What It Does

This server adds a validation layer you can run before shipping. You paste a YARA-L rule, it extracts the exact UDM conditions required to trigger it, generates synthetic correlated events that satisfy those conditions, ingests them into your SecOps instance via UDM import (no parser delay), and confirms a detection fires. Optionally, it also generates near-miss events and proves the rule **does not** fire on them.

Five validation modes:

| Mode | What it proves | Speed |
|------|----------------|-------|
| **Positive** | Rule fires when the attack pattern is present | <5 min |
| **Negative** | Rule stays quiet on near-miss traffic (not over-broad) | <5 min |
| **Fixture replay** | Deterministic re-run using cached events instead of regenerating | <5 min |
| **Batch** | Pass/fail matrix across many rules in one go | <5 min per rule |
| **Composite cascade** | Upstream rules fire → downstream composite rule fires | **up to 1h (HOURLY) or 24h (DAILY)** |

Composite cascade is supported but slow — Chronicle schedules composite evaluation on HOURLY (windows 1–24h) or DAILY (windows ≥24h) cadences and rejects retrohunts on composites, so there is no fast path through Chronicle's cascade evaluator. The UI warns up-front with the expected wait (derived from the rule's match window) before ingesting the cascade, and keeps polling until the next scheduled run lands or the wait expires.

**CI fast-path for composites.** For PR-blocking checks where a 1-24 hour wait is unacceptable, use `composite_static_validate` (tool) or `/api/composite-static-validate` (HTTP). It validates each referenced base rule end-to-end and runs a structural check on the composite (join keys, window, ordering), then returns immediately. It does NOT prove Chronicle will chain the cascade on its schedule. Pair it with a nightly `cascade_validate` job to cover both.

## The Workflow

```
Write / convert rule → YARA-L
         ↓
Run through YARA-L Validator
         ↓
Positive: rule fires on attack traffic
Negative: rule stays quiet on near-miss traffic
         ↓
Cache as fixture → deterministic regression tests forever
         ↓
Ship with proof
```

You go from "I assume this rule works" to "I have proof this rule fires on the attack pattern and does not fire on the near-miss pattern" — before the customer's data ever touches the environment.

## Architecture

```
Browser UI ──► FastAPI Server ──► Gemini (rule analysis + event generation)
                    │
                    ├──► Google SecOps SDK (UDM ingest + detection polling)
                    │
                    └──► Fixture Store (cached events for replay)
```

UDM events are ingested via `events:import` directly. Parsing is skipped entirely, so detections evaluate as soon as SecOps runs the next rule pass (usually under 60 seconds for LIVE frequency rules).

> **Two ingestion paths.** UDM direct is fast (60-120s) and proves the rule's UDM conditions match a well-formed payload. It does NOT prove your production parser produces the expected UDM shape. Parser path (new) generates raw native logs in the source format (Windows Event XML, Okta JSON, GCP Cloud Audit JSON, etc.), ingests via `ingest_log`, and lets Chronicle's parser run. Slower (5+ minutes) but catches parser-vs-rule mismatches. Select per-validation via the "Ingestion path" dropdown in the UI, `--validation-mode` on the CLI, or the `validation_mode` parameter on `/api/validate`. Set `both` to gate on both paths. See [docs/COVERAGE.md](docs/COVERAGE.md#ingestion-path) for the full list.

## Tools (MCP)

**Core validation**
| Tool | Description |
|------|-------------|
| `analyze_yara_l_rule` | Extracts trigger conditions, event types, and entity joins |
| `generate_synthetic_events` | Synthesizes UDM events that satisfy the rule |
| `ingest_synthetic_events` | Imports events into SecOps via UDM (no parser) |
| `ensure_rule_live` | Flips the rule to LIVE so detections evaluate in near-real-time |
| `verify_rule_triggered` | Polls detections, returns plain-English summary |
| `run_full_validation` | Orchestrates analyze → generate → ingest → verify |

**Negative / false-positive testing**
| Tool | Description |
|------|-------------|
| `generate_negative_events` | Generates near-miss scenarios that should NOT trigger the rule |
| `ingest_negative_scenario` | Ingests a single near-miss scenario |
| `verify_rule_quiet` | Asserts no detection fired (inverse of verify) |

**Fixture caching**
| Tool | Description |
|------|-------------|
| `save_fixture` | Persists generated events as a named fixture |
| `load_fixture` | Replays a fixture with refreshed timestamps |
| `list_fixtures` | Lists all saved fixtures |

**Batch**
| Tool | Description |
|------|-------------|
| `batch_validate` | Runs positive (and optional negative) validation across a list of rules and returns a pass/fail matrix |

**Composite detections**
| Tool | Description |
|------|-------------|
| `analyze_composite_rule` | Detects rule chains and explains structure (base components, join keys, ordering, window) |
| `generate_cascade_events` | Generates event sets that trigger each base rule in the chain |
| `cascade_validate` | End-to-end: analyzes, generates, ingests — then returns a wait estimate (up to 1h HOURLY or 24h DAILY). Client polls on the matching cadence until the composite fires. |
| `composite_static_validate` | CI fast path: validates every referenced base rule individually + a structural check on the composite, returns immediately. Skips Chronicle's cascade scheduler. Pair with a nightly `cascade_validate` for full coverage. |

## Detection Summaries

Detections come back as plain English instead of raw JSON:

> jsmith from 10.0.0.10 failed 5 login attempts between 01:36:08 and 01:40:08 UTC, then successfully logged in at 01:41:08 UTC.

You can still get raw JSON from the API for programmatic consumers.

## Prerequisites

- Google Cloud project with Google SecOps enabled
- SecOps customer ID (Settings → SIEM Settings → Profile)
- Vertex AI API enabled (for Gemini)
- Application Default Credentials with `roles/chronicle.admin` or equivalent

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECOPS_PROJECT_ID` | Yes | GCP project ID |
| `SECOPS_CUSTOMER_ID` | Yes | SecOps instance UUID |
| `SECOPS_REGION` | No | SecOps region (default: `us`) |
| `GEMINI_MODEL` | No | Gemini model (default: `gemini-2.5-flash`) |
| `OAUTH_CLIENT_ID` | No | Google OAuth client ID — if set, login required |
| `ALLOWED_EMAILS` | No | Comma-separated list of allowed Google emails |
| `PORT` | No | HTTP port (default: `8080`) |
| `DETERMINISTIC` | No | `1` pins Gemini temperature to 0 and caches responses by `sha256(model, system, prompt, max_tokens)`. Use in CI so identical rules produce identical events run-to-run. |
| `METRICS_PATH` | No | File path for aggregate metrics snapshot (default: `./metrics.json`). |
| `FIXTURE_BACKEND` | No | `gcs` to store fixtures in `$FIXTURE_BUCKET`; otherwise local filesystem at `./fixtures/`. |

## Deploy to Cloud Run

```bash
git clone https://github.com/dadohen/yaral-validator-mcp.git
cd yaral-validator-mcp

gcloud builds submit --tag gcr.io/YOUR_PROJECT/yaral-validator:latest .

gcloud run deploy yaral-validator \
  --image gcr.io/YOUR_PROJECT/yaral-validator:latest \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --memory 512Mi \
  --timeout 300 \
  --set-env-vars "SECOPS_PROJECT_ID=YOUR_PROJECT,SECOPS_CUSTOMER_ID=YOUR_SECOPS_UUID,SECOPS_REGION=us,GEMINI_MODEL=gemini-2.5-flash"
```

**Caveat on Cloud Run:** the fixture store writes to the container's local filesystem, which is wiped on every deploy and scale-to-zero. Fixtures survive within a warm pod's lifetime but do not persist across restarts. If you need durable fixtures, mount GCS or swap the store to Firestore.

## Run Locally

```bash
git clone https://github.com/dadohen/yaral-validator-mcp.git
cd yaral-validator-mcp

pip install -r requirements.txt
gcloud auth application-default login

export SECOPS_PROJECT_ID=your-project
export SECOPS_CUSTOMER_ID=your-secops-uuid
export SECOPS_REGION=us

python3 main.py
```

Open `http://localhost:8080`. Fixtures persist in `./fixtures/` across restarts when running locally.

## Usage

### Web UI

1. Paste your YARA-L rule into the left panel
2. Click **Analyze Rule** to extract trigger conditions
3. Click **⚡ Events** to generate synthetic UDM traffic
4. Click **📤 Ingest** to send to SecOps
5. Click **✅ Verify** to confirm the detection fired (auto-polls)

Or click **🚀 Full Validation** to run the whole pipeline. Enable the **Negative** toggle to also run false-positive tests. Passing validations are cached as fixtures automatically.

Additional buttons:
- **🔗 Composite Validate** — end-to-end cascade validation for multi-stage rules. Analyzes structure, shows the expected wait (up to 1h HOURLY, up to 24h DAILY), asks for confirmation, then ingests the cascade and polls until it fires. Slow by design — see "What It Is Not" for why.
- **📦 Batch** — paste a list of rules, get a pass/fail matrix
- **📂 Fixtures** — browse saved fixtures and replay any of them
- **💾 Save** — manually cache the current generated events

### Chat

Natural language in the right panel:

> *"Run full validation on this rule and also check for false positives"*
> *"Load the fixture for detect_lateral_movement and re-verify"*
> *"Batch validate all 5 rules I just pasted"*

### CI / PR validation

For detection teams that keep YARA-L rules in Git, the `cli/` directory ships
a `validate_changed.py` script and a GitHub Action template
(`.github/workflows/validate-rules.yml`) that validates only the rules that
changed in a PR and comments a pass/fail matrix. Composite rules are skipped
because their validation takes up to 24 hours; run those in a nightly job.

See [cli/README.md](cli/README.md) for setup (workload identity federation,
required secrets, flag reference) and [docs/COVERAGE.md](docs/COVERAGE.md)
for what YARA-L constructs the validator actually covers.

## What It Is Not

Honest scope so you don't get surprised:

- **Not a rule linter.** Syntax and style are out of scope — use Google's built-in rule editor for that.
- **Not a replacement for production telemetry.** Synthetic events prove the rule *can* fire on the pattern you described. Real data can still surface corner cases the synthetic generator didn't think of.
- **Not deterministic by default.** Gemini generation varies run-to-run; use fixture caching to lock an event set for regression tests.
- **Negative testing is bounded by imagination.** The tool generates five perturbation axes (threshold, entity, time window, action, missing event type). It won't catch every false-positive class — only the ones it knows how to perturb.
- **Not a <5-minute composite validator.** Composite / cascade rules (those referencing `$var.detection.*` or other rules by name) *are* validated end-to-end, but slowly. Chronicle schedules composite evaluation on HOURLY cadence for match windows 1–24h and DAILY cadence for windows ≥24h, and retrohunts on composite rules don't work — so the worst-case wait is up to 1 hour (HOURLY) or up to 24 hours (DAILY). The tool tells you the expected wait up front, asks for confirmation, and then polls until the cascade fires or the wait expires. If you need faster feedback, validate each base rule here individually (that path is <5 min) and deploy the composite separately.

## Security

- Security headers on all responses (CSP, HSTS, X-Frame-Options)
- Optional Google OAuth — set `OAUTH_CLIENT_ID` to require login
- No credentials stored in code — uses Application Default Credentials
- Fixtures are stored locally on the server — do not commit real customer event data into a public fixtures directory

## Finding Your SecOps Customer ID

In the SecOps UI: **Settings → SIEM Settings → Profile**. Customer ID is a UUID (e.g. `1d49deb2-eaa7-427c-a1d1-e78ccaa91c10`).
