"""
YARA-L Detection Validator MCP Server
Upload a YARA-L rule → analyze required events → generate synthetic UDM traffic →
ingest into Chronicle → verify the rule fired. Full detection validation pipeline.
"""

import json
import os
import re
import uuid
import time
import logging
import requests
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from mcp.server.fastmcp import FastMCP

# ── CONFIG ──────────────────────────────────────────────────────
SECOPS_PROJECT_ID  = os.getenv("SECOPS_PROJECT_ID", "")
SECOPS_CUSTOMER_ID = os.getenv("SECOPS_CUSTOMER_ID", "")
SECOPS_REGION      = os.getenv("SECOPS_REGION", "us")
GEMINI_MODEL       = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
OAUTH_CLIENT_ID    = os.getenv("OAUTH_CLIENT_ID", "")
ALLOWED_EMAILS     = set(e.strip() for e in os.getenv("ALLOWED_EMAILS", "carter@linus.joonix.net,dnehoda@gmail.com").split(",") if e.strip())
PORT               = int(os.getenv("PORT", "8080"))

CHRONICLE_BASE = (
    f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1alpha"
    f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}/instances/{SECOPS_CUSTOMER_ID}"
)

logging.basicConfig(level=logging.INFO, format='{"severity":"%(levelname)s","message":"%(message)s"}')
logger = logging.getLogger(__name__)

# ── MCP ─────────────────────────────────────────────────────────
app_mcp = FastMCP("yaral-validator")

# ── SESSION STORE ────────────────────────────────────────────────
class SessionStore:
    def __init__(self):
        self.sessions: dict = {}

    def get_or_create(self, sid: str) -> dict:
        if sid not in self.sessions:
            self.sessions[sid] = {"chat_history": [], "validations": []}
        return self.sessions[sid]

    def append_history(self, sid: str, role: str, text: str):
        s = self.get_or_create(sid)
        s["chat_history"].append({"role": role, "parts": [{"text": text}]})
        if len(s["chat_history"]) > 30:
            s["chat_history"] = s["chat_history"][-30:]

    def get_history(self, sid: str) -> list:
        return self.sessions.get(sid, {}).get("chat_history", [])

    def add_validation(self, sid: str, record: dict):
        s = self.get_or_create(sid)
        s["validations"].append(record)

    def get_validations(self, sid: str) -> list:
        return self.sessions.get(sid, {}).get("validations", [])

session_store = SessionStore()

# ── AUTH ─────────────────────────────────────────────────────────
def _get_adc_token() -> str:
    import google.auth, google.auth.transport.requests
    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    creds.refresh(google.auth.transport.requests.Request())
    return creds.token

def _verify_google_token(request: Request) -> str | None:
    if not OAUTH_CLIENT_ID:
        return "dev"
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        from google.oauth2 import id_token as gid
        from google.auth.transport import requests as gr
        info = gid.verify_oauth2_token(auth[7:], gr.Request(), OAUTH_CLIENT_ID)
        email = info.get("email", "")
        if ALLOWED_EMAILS and email not in ALLOWED_EMAILS:
            return None
        return email
    except Exception as e:
        logger.warning(f"Token verify failed: {e}")
        return None

def _extract_json(text: str) -> any:
    """Strip markdown fences and parse JSON, repairing common escape issues."""
    # Remove ```json ... ``` or ``` ... ``` blocks
    text = re.sub(r'^```(?:json)?\s*', '', text.strip(), flags=re.MULTILINE)
    text = re.sub(r'\s*```\s*$', '', text, flags=re.MULTILINE)
    text = text.strip()
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Extract the outermost { } or [ ] block
    for start_ch, end_ch in [('{', '}'), ('[', ']')]:
        start = text.find(start_ch)
        end = text.rfind(end_ch)
        if start != -1 and end > start:
            candidate = text[start:end + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                # Fix invalid escape sequences (e.g. \b \p \/ not valid in JSON strings)
                fixed = re.sub(r'(?<!\\)\\(?!["\\/bfnrtu])', r'\\\\', candidate)
                try:
                    return json.loads(fixed)
                except json.JSONDecodeError:
                    pass
    raise ValueError(f"Could not extract valid JSON from Gemini response: {text[:200]}")


def _gemini(prompt: str, system: str = "") -> str:
    """Call Gemini and return text."""
    token = _get_adc_token()
    url = (f"https://us-central1-aiplatform.googleapis.com/v1/projects/{SECOPS_PROJECT_ID}"
           f"/locations/us-central1/publishers/google/models/{GEMINI_MODEL}:generateContent")
    body: dict = {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}
    if system:
        body["systemInstruction"] = {"parts": [{"text": system}]}
    resp = requests.post(url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                         json=body, timeout=60)
    if resp.status_code != 200:
        raise RuntimeError(f"Gemini error {resp.status_code}: {resp.text[:300]}")
    parts = resp.json().get("candidates", [{}])[0].get("content", {}).get("parts", [])
    return "".join(p.get("text", "") for p in parts)

# ═══════════════════════════════════════════════════════════════
# MCP TOOLS
# ═══════════════════════════════════════════════════════════════

@app_mcp.tool()
def analyze_yara_l_rule(rule_text: str) -> str:
    """Analyze a YARA-L rule and extract what UDM events, field conditions, and entity
    relationships are needed to trigger it. Returns structured analysis with trigger requirements."""
    prompt = f"""Analyze this YARA-L rule and return a JSON object with these fields:
- rule_name: the rule name
- description: what threat this rule detects
- event_variables: list of event variable names (e.g. $e, $e1, $e2)
- required_events: list of objects with {{variable, event_type, description}}
- required_fields: list of objects with {{field, operator, value, description}}
- entity_joins: any joins between event variables (e.g. $e1.principal.ip = $e2.target.ip)
- time_window: match time window if any
- outcome_fields: any outcome variables set
- trigger_summary: plain English — exactly what sequence of events triggers this rule
- synthetic_event_hints: specific field values to use when generating test events

YARA-L Rule:
```
{rule_text}
```

Return ONLY valid JSON, no markdown."""

    try:
        result = _gemini(prompt)
        parsed = _extract_json(result)
        parsed["raw_rule"] = rule_text
        return json.dumps(parsed, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "raw_rule": rule_text})


@app_mcp.tool()
def generate_synthetic_events(analysis_json: str, count: int = 5) -> str:
    """Given the output of analyze_yara_l_rule, generate synthetic UDM events that will
    trigger the rule. Returns a list of UDM event objects ready for Chronicle ingestion."""
    try:
        analysis = json.loads(analysis_json) if isinstance(analysis_json, str) else analysis_json
    except Exception:
        analysis = {"trigger_summary": analysis_json}

    prompt = f"""Generate exactly {count} synthetic UDM (Unified Data Model) events in JSON format
that together will trigger this YARA-L rule.

Rule analysis:
{json.dumps(analysis, indent=2)}

Requirements:
- Each event MUST satisfy the field conditions in required_fields
- Use realistic but fake values (IPs like 10.0.0.x, hostnames like test-host-01)
- Include metadata.event_timestamp in RFC3339 format (within last 10 minutes)
- Include metadata.id as a unique UUID per event
- Include metadata.product_name: "SYNTHETIC_TEST"
- Include metadata.ingestion_labels: {{"validation_id": "yaral-test-{uuid.uuid4().hex[:8]}"}}
- If the rule requires multiple event types or entity joins, generate correlated events
  (same principal.ip or hostname across events as needed)

Return ONLY a valid JSON array of UDM event objects. No markdown, no explanation."""

    try:
        result = _gemini(prompt)
        events = _extract_json(result)
        if not isinstance(events, list):
            events = [events]
        # Stamp each event with a test marker
        for e in events:
            e.setdefault("metadata", {})
            e["metadata"]["product_name"] = "YARAL_VALIDATOR_SYNTHETIC"
        return json.dumps({"events": events, "count": len(events)})
    except Exception as ex:
        return json.dumps({"error": str(ex)})


@app_mcp.tool()
def ingest_synthetic_events(events_json: str) -> str:
    """Ingest synthetic UDM events into Chronicle for rule testing.
    Accepts the output of generate_synthetic_events or a raw JSON array of UDM events.
    Returns ingestion status and a validation_id to track this test run."""
    try:
        data = json.loads(events_json) if isinstance(events_json, str) else events_json
        events = data.get("events", data) if isinstance(data, dict) else data
        if not isinstance(events, list):
            return json.dumps({"error": "Expected a list of UDM events"})

        validation_id = f"yaral-test-{uuid.uuid4().hex[:12]}"
        ingestion_time = datetime.now(timezone.utc).isoformat()

        # Stamp all events with the validation ID for later lookup
        for e in events:
            e.setdefault("metadata", {})
            e["metadata"]["product_name"] = "YARAL_VALIDATOR_SYNTHETIC"
            e["metadata"].setdefault("ingestion_labels", {})["validation_id"] = validation_id
            if "event_timestamp" not in e["metadata"]:
                e["metadata"]["event_timestamp"] = ingestion_time

        import google.auth, google.auth.transport.requests
        creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        from secops import SecOpsClient
        from secops.auth import SecOpsAuth
        client = SecOpsClient(credentials=creds).chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION,
        )
        result = client.ingest_udm(events)
        return json.dumps({
            "status": "ingested",
            "validation_id": validation_id,
            "event_count": len(events),
            "ingestion_time": ingestion_time,
            "api_response": result,
            "message": f"Ingested {len(events)} synthetic events via SecOps SDK. Wait 2-5 min then verify."
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def verify_rule_triggered(rule_name: str, minutes_back: int = 10, validation_id: str = "") -> str:
    """Poll Chronicle detections to check if a rule fired after synthetic event ingestion.
    rule_name: exact name of the YARA-L rule to check.
    minutes_back: how far back to look for detections (default 10 minutes).
    validation_id: optional — filter detections to only this test run."""
    try:
        token = _get_adc_token()
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=minutes_back)

        # List detections for the rule
        detections_url = f"{CHRONICLE_BASE}/rules/{rule_name}/detections"
        params = {
            "startTime": start_time.isoformat(),
            "endTime": end_time.isoformat(),
            "pageSize": 20,
        }
        resp = requests.get(detections_url, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=30)

        if resp.status_code == 200:
            detections = resp.json().get("detections", [])
            matched = detections
            if validation_id:
                matched = [d for d in detections if validation_id in json.dumps(d)]

            return json.dumps({
                "rule_name": rule_name,
                "validation_id": validation_id,
                "detection_found": len(matched) > 0,
                "detection_count": len(matched),
                "total_detections_in_window": len(detections),
                "time_window_minutes": minutes_back,
                "detections": matched[:5],
                "verdict": "PASS ✅ — Rule fired on synthetic events" if matched else
                           f"PENDING ⏳ — No detections yet. Chronicle may still be processing. Try again in 2 minutes." if len(detections) == 0 else
                           "PARTIAL ⚠️ — Rule has detections but none match this validation run"
            })

        # Fallback: search via UDM detections search
        search_url = f"{CHRONICLE_BASE}/detections:search"
        search_body = {
            "timeRange": {"startTime": start_time.isoformat(), "endTime": end_time.isoformat()},
            "filter": f'rule.name = "{rule_name}"',
            "pageSize": 10,
        }
        resp2 = requests.post(search_url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                              json=search_body, timeout=30)
        if resp2.status_code == 200:
            results = resp2.json().get("detections", [])
            return json.dumps({
                "rule_name": rule_name,
                "detection_found": len(results) > 0,
                "detection_count": len(results),
                "verdict": "PASS ✅" if results else "PENDING ⏳ — Not yet detected",
                "detections": results[:3],
            })

        return json.dumps({"error": f"Detection check failed [{resp.status_code}]: {resp.text[:300]}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def run_full_validation(rule_text: str, rule_name: str = "", wait_seconds: int = 120) -> str:
    """End-to-end YARA-L rule validation pipeline:
    1. Analyze the rule to extract trigger conditions
    2. Generate synthetic UDM events that satisfy those conditions
    3. Ingest events into Chronicle
    4. Wait for rule evaluation
    5. Verify the rule fired
    Returns a full validation report with pass/fail verdict."""
    results = {}
    try:
        # Step 1: Analyze
        logger.info("Step 1: Analyzing YARA-L rule...")
        analysis_raw = analyze_yara_l_rule(rule_text)
        analysis = json.loads(analysis_raw)
        results["analysis"] = analysis
        detected_name = analysis.get("rule_name", rule_name or "unknown_rule")
        if not rule_name:
            rule_name = detected_name

        # Step 2: Generate events
        logger.info("Step 2: Generating synthetic events...")
        events_raw = generate_synthetic_events(analysis_raw, count=5)
        events_data = json.loads(events_raw)
        results["generation"] = events_data
        if "error" in events_data:
            return json.dumps({"status": "FAILED", "stage": "generation", "results": results})

        # Step 3: Ingest
        logger.info("Step 3: Ingesting events into Chronicle...")
        ingest_raw = ingest_synthetic_events(events_raw)
        ingest_data = json.loads(ingest_raw)
        results["ingestion"] = ingest_data
        validation_id = ingest_data.get("validation_id", "")
        if ingest_data.get("status") not in ["ingested", "ingested_fallback"]:
            return json.dumps({"status": "FAILED", "stage": "ingestion", "results": results})

        # Step 4: Wait
        logger.info(f"Step 4: Waiting {wait_seconds}s for Chronicle rule evaluation...")
        results["wait"] = {"seconds": wait_seconds, "message": f"Waiting {wait_seconds}s for Chronicle to evaluate..."}

        # We can't block Cloud Run for 2 min, so return interim result with verification instructions
        return json.dumps({
            "status": "INGESTED_AWAITING_VERIFICATION",
            "rule_name": rule_name,
            "validation_id": validation_id,
            "event_count": events_data.get("count", 0),
            "next_step": f"Call verify_rule_triggered(rule_name='{rule_name}', validation_id='{validation_id}') in {wait_seconds//60}-{wait_seconds//60+3} minutes",
            "results": results,
            "ingestion_time": ingest_data.get("ingestion_time", ""),
        })
    except Exception as e:
        results["error"] = str(e)
        return json.dumps({"status": "ERROR", "error": str(e), "results": results})


# ═══════════════════════════════════════════════════════════════
# FASTAPI
# ═══════════════════════════════════════════════════════════════

app = FastAPI(title="YARA-L Detection Validator")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://accounts.google.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; "
            "connect-src 'self'; frame-src https://accounts.google.com; frame-ancestors 'none';"
        )
        response.headers["Server"] = "yaral-validator"
        return response

app.add_middleware(SecurityHeadersMiddleware)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0", "service": "yaral-validator",
            "chronicle_project": SECOPS_PROJECT_ID, "chronicle_customer": SECOPS_CUSTOMER_ID}


@app.get("/api/auth-config")
async def auth_config():
    return {"client_id": OAUTH_CLIENT_ID, "auth_required": bool(OAUTH_CLIENT_ID)}


@app.get("/api/history")
async def api_history(request: Request):
    sid = request.cookies.get("yv_session", "")
    return JSONResponse({"validations": session_store.get_validations(sid)})


@app.post("/api/analyze")
async def api_analyze(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    rule_text = body.get("rule", "").strip()
    if not rule_text:
        return JSONResponse({"error": "No rule provided"}, status_code=400)
    result = analyze_yara_l_rule(rule_text)
    return JSONResponse(json.loads(result))


@app.post("/api/generate")
async def api_generate(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    analysis_json = body.get("analysis_json", "")
    count = int(body.get("count", 5))
    if not analysis_json:
        return JSONResponse({"error": "No analysis provided"}, status_code=400)
    result = generate_synthetic_events(analysis_json, count=count)
    return JSONResponse(json.loads(result))


@app.post("/api/ingest")
async def api_ingest(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    events_json = body.get("events_json", "")
    if not events_json:
        return JSONResponse({"error": "No events provided"}, status_code=400)
    result = ingest_synthetic_events(events_json)
    return JSONResponse(json.loads(result))


@app.post("/api/validate")
async def api_validate(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    rule_text = body.get("rule", "").strip()
    rule_name = body.get("rule_name", "")
    session_id = body.get("session_id") or request.cookies.get("yv_session") or str(uuid.uuid4())
    if not rule_text:
        return JSONResponse({"error": "No rule provided"}, status_code=400)
    result_raw = run_full_validation(rule_text, rule_name=rule_name)
    result = json.loads(result_raw)
    session_store.add_validation(session_id, {"ts": datetime.now(timezone.utc).isoformat(), **result})
    resp = JSONResponse(result)
    resp.set_cookie("yv_session", session_id, max_age=86400, samesite="lax")
    return resp


@app.post("/api/verify")
async def api_verify(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    rule_name = body.get("rule_name", "")
    validation_id = body.get("validation_id", "")
    minutes_back = int(body.get("minutes_back", 10))
    result = verify_rule_triggered(rule_name, minutes_back=minutes_back, validation_id=validation_id)
    return JSONResponse(json.loads(result))


@app.post("/api/chat")
async def api_chat(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    message = body.get("message", "").strip()
    if not message:
        return JSONResponse({"error": "No message"}, status_code=400)
    session_id = body.get("session_id") or request.cookies.get("yv_session") or str(uuid.uuid4())
    session_store.get_or_create(session_id)

    try:
        all_tools = list(app_mcp._tool_manager.list_tools())
        tool_decls = []
        for t in all_tools:
            props, req = {}, []
            if hasattr(t, "inputSchema") and isinstance(t.inputSchema, dict):
                props = t.inputSchema.get("properties", {})
                req = t.inputSchema.get("required", [])
            tool_decls.append({"name": t.name, "description": t.description or "",
                                "parameters": {"type": "object", "properties": props, "required": req}})

        token = _get_adc_token()
        gemini_url = (f"https://us-central1-aiplatform.googleapis.com/v1/projects/{SECOPS_PROJECT_ID}"
                      f"/locations/us-central1/publishers/google/models/{GEMINI_MODEL}:generateContent")
        headers_ai = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        system_text = (
            "You are a detection engineering expert specializing in YARA-L rule validation.\n\n"
            "TOOL ROUTING:\n"
            "- 'analyze rule / what does this rule detect / parse rule' → analyze_yara_l_rule\n"
            "- 'generate events / create test traffic / synthetic events' → generate_synthetic_events\n"
            "- 'ingest / send events / upload to Chronicle' → ingest_synthetic_events\n"
            "- 'check / verify / did rule fire / detection results' → verify_rule_triggered\n"
            "- 'validate / test / run full test / end to end' → run_full_validation\n\n"
            "RULES:\n"
            "- When user pastes a YARA-L rule, always analyze it first with analyze_yara_l_rule\n"
            "- For full validation, use run_full_validation then tell the user to call verify in 2-5 minutes\n"
            "- Explain what synthetic events were generated and why they satisfy the rule conditions\n"
            "- After verify, clearly state PASS or FAIL with explanation\n"
        )

        history = session_store.get_history(session_id)
        contents = history + [{"role": "user", "parts": [{"text": message}]}]
        tool_log = []
        final_text = ""

        for _ in range(6):
            resp = requests.post(gemini_url, headers=headers_ai,
                                 json={"contents": contents,
                                       "tools": [{"functionDeclarations": tool_decls}],
                                       "systemInstruction": {"parts": [{"text": system_text}]}},
                                 timeout=120)
            if resp.status_code != 200:
                return JSONResponse({"error": f"AI [{resp.status_code}]: {resp.text[:200]}"})

            candidates = resp.json().get("candidates", [])
            if not candidates:
                break
            content_data = candidates[0].get("content", {})
            parts = content_data.get("parts", [])
            contents.append(content_data)

            has_tool = any("functionCall" in p for p in parts)
            if not has_tool:
                for p in parts:
                    if "text" in p:
                        final_text += p["text"] + "\n"
                break

            tool_responses = []
            for p in parts:
                if "functionCall" not in p:
                    continue
                tname = p["functionCall"]["name"]
                targs = p["functionCall"].get("args", {})
                try:
                    tobj = app_mcp._tool_manager._tools.get(tname)
                    result_text = tobj.fn(**targs) if tobj else f"Tool {tname} not found"
                    if not isinstance(result_text, str):
                        result_text = str(result_text)
                    tool_log.append({"tool": tname, "result": result_text[:500]})
                    tool_responses.append({"functionResponse": {"name": tname, "response": {"result": result_text}}})
                except Exception as e:
                    tool_log.append({"tool": tname, "error": str(e)})
                    tool_responses.append({"functionResponse": {"name": tname, "response": {"error": str(e)}}})
            contents.append({"role": "user", "parts": tool_responses})

        session_store.append_history(session_id, "user", message)
        session_store.append_history(session_id, "model", final_text.strip() or "Done.")

        resp_out = JSONResponse({"response": final_text.strip() or "Done.", "tool_log": tool_log, "session_id": session_id})
        resp_out.set_cookie("yv_session", session_id, max_age=86400, samesite="lax")
        return resp_out

    except Exception as e:
        logger.error(f"Chat error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# Mount static and MCP
app.mount("/mcp", app_mcp.sse_app())
app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
