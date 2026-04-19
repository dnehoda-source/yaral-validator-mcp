# YARA-L Detection Validator MCP Server

A detection engineering tool that validates YARA-L rules against Google SecOps by generating synthetic UDM events, ingesting them, and verifying the rule actually fires — all through a web UI or natural language chat.

## What It Does

Writing a YARA-L detection rule is one thing. Knowing it works is another. This server closes that gap by running a full end-to-end validation pipeline:

1. **Analyze** — Parses your YARA-L rule and extracts the exact UDM field conditions, event types, and entity joins required to trigger it
2. **Generate** — Uses Gemini to synthesize realistic UDM events that satisfy those conditions
3. **Ingest** — Sends the events into your SecOps instance via the SecOps SDK
4. **Verify** — Polls SecOps detections to confirm the rule fired on the synthetic traffic

Without this, you're deploying detection rules into production and hoping they work. With this, you have proof before you ship.

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
