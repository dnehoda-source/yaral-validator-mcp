# YARA-L Detection Validator MCP Server

A detection engineering tool that validates YARA-L rules against Google SecOps by generating synthetic UDM events, ingesting them, and verifying the rule actually fires — all through a web UI or natural language chat.

## The Problem

Google SecOps has test rule and retrohunt — both useful, but both require existing production data to run against. That works in a live environment.

It does not work during a SIEM migration.

When you're converting a customer from a legacy SIEM to SecOps, you have no historical events, no ingested logs, and no production data. You're configuring an entire detection layer on an empty environment with no way to verify that a converted YARA-L rule will actually fire, generate a detection, and surface a case for investigation. You find out if it works when real data starts flowing — which is also when it matters most.

That's not a testing strategy. That's a liability handed to the customer at go-live.

**The gap exists because:**
- Test rule and retrohunt require data that doesn't exist yet in a new environment
- Manually crafting UDM events to test a rule requires deep platform knowledge and significant time per rule
- A rule can be syntactically valid, pass a linter, and still never fire because a field mapping is wrong or a condition doesn't match how the data source actually formats events
- There is no standard validation step in the SIEM migration workflow — rules are converted and shipped with the assumption they work

## What It Does

This server adds a validation step to the migration workflow. You paste a converted YARA-L rule, it analyzes the exact UDM field conditions required to trigger it, generates synthetic correlated events that satisfy those conditions, ingests them into SecOps, and verifies that a detection fires and a case is created — no production data required.

1. **Analyze** — Parses your YARA-L rule and extracts the exact UDM field conditions, event types, and entity joins required to trigger it
2. **Generate** — Uses Gemini to synthesize realistic UDM events that satisfy those conditions
3. **Ingest** — Sends the events into your SecOps instance via the SecOps SDK
4. **Verify** — Confirms a detection fired and a case was created

**The migration validation workflow becomes:**

```
Convert rule from legacy SIEM → YARA-L
         ↓
Run through YARA-L Validator
         ↓
Confirm detection fires and case is created
         ↓
Ship with confidence
```

You go from "I assume this rule works" to "I have proof this rule works" — before the customer's data ever touches the environment.

## Architecture

```
Browser UI ──► FastAPI Server ──► Gemini (analysis + event generation)
                    │
                    └──► Google SecOps SDK (ingest + verify)
```

**Tools exposed (MCP):**
| Tool | Description |
|------|-------------|
| `analyze_yara_l_rule` | Extracts trigger conditions from a YARA-L rule |
| `generate_synthetic_events` | Generates correlated UDM events that satisfy rule conditions |
| `ingest_synthetic_events` | Ingests events into SecOps via the SecOps SDK |
| `verify_rule_triggered` | Polls SecOps detections to confirm the rule fired |
| `run_full_validation` | Orchestrates the full pipeline in one call |

## Prerequisites

- Google Cloud project with Google SecOps enabled
- SecOps customer ID (see below)
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

## Deploy to Cloud Run

```bash
git clone https://github.com/dnehoda-source/yaral-validator-mcp.git
cd yaral-validator-mcp

# Build and push image
gcloud builds submit --tag gcr.io/YOUR_PROJECT/yaral-validator:latest .

# Deploy
gcloud run deploy yaral-validator \
  --image gcr.io/YOUR_PROJECT/yaral-validator:latest \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --memory 512Mi \
  --timeout 300 \
  --set-env-vars "SECOPS_PROJECT_ID=YOUR_PROJECT,SECOPS_CUSTOMER_ID=YOUR_SECOPS_UUID,SECOPS_REGION=us,GEMINI_MODEL=gemini-2.5-flash"
```

## Run Locally

```bash
git clone https://github.com/dnehoda-source/yaral-validator-mcp.git
cd yaral-validator-mcp

pip install -r requirements.txt

# Authenticate with Google
gcloud auth application-default login

export SECOPS_PROJECT_ID=your-project
export SECOPS_CUSTOMER_ID=your-secops-uuid
export SECOPS_REGION=us

python3 main.py
```

Open `http://localhost:8080`

## Usage

### Web UI

1. Paste your YARA-L rule into the left panel
2. Click **Analyze Rule** to extract trigger conditions
3. Click **⚡ Events** to generate synthetic UDM traffic
4. Click **📤 Ingest Synthetic Events** to send to SecOps
5. Wait 2-5 minutes for SecOps to evaluate the rule
6. Click **✅ Verify Rule Fired** to check detections

Or click **🚀 Full Validation Pipeline** to run steps 1-4 automatically.

### Chat

Use the right panel to interact in natural language:
- *"Analyze this rule and tell me what events will trigger it"*
- *"Generate 10 synthetic events for this rule"*
- *"Check if rule detect_lateral_movement fired in the last 15 minutes"*

## Security

- Security headers on all responses (CSP, HSTS, X-Frame-Options, etc.)
- Optional Google OAuth — set `OAUTH_CLIENT_ID` to require login
- No credentials stored in code — uses Application Default Credentials

## Finding Your SecOps Customer ID

In the SecOps UI: **Settings → SIEM Settings → Profile**

Your customer ID is listed there as a UUID (e.g. `1d49deb2-eaa7-427c-a1d1-e78ccaa91c10`).
