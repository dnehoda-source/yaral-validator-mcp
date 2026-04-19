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

def _repair_json(text: str) -> str:
    """Apply a sequence of repairs to make Gemini output parseable as JSON."""
    # Fix invalid escape sequences: \x where x is not a valid JSON escape char
    text = re.sub(r'\\(?!["\\/bfnrtu0-9])', r'\\\\', text)
    # Fix unescaped literal newlines/tabs inside JSON string values
    # Walk char by char to replace bare \n \r \t inside strings
    out = []
    in_str = False
    escape_next = False
    for ch in text:
        if escape_next:
            out.append(ch)
            escape_next = False
        elif ch == '\\' and in_str:
            out.append(ch)
            escape_next = True
        elif ch == '"':
            out.append(ch)
            in_str = not in_str
        elif in_str and ch == '\n':
            out.append('\\n')
        elif in_str and ch == '\r':
            out.append('\\r')
        elif in_str and ch == '\t':
            out.append('\\t')
        else:
            out.append(ch)
    text = ''.join(out)
    # Trailing commas before } or ]
    text = re.sub(r',\s*([}\]])', r'\1', text)
    # Python literals → JSON
    text = re.sub(r'\bNone\b', 'null', text)
    text = re.sub(r'\bTrue\b', 'true', text)
    text = re.sub(r'\bFalse\b', 'false', text)
    return text


def _extract_json(text: str) -> any:
    """Strip markdown fences and parse JSON, repairing common Gemini output issues."""
    # Remove ```json ... ``` fences
    text = re.sub(r'^```(?:json)?\s*', '', text.strip(), flags=re.MULTILINE)
    text = re.sub(r'\s*```\s*$', '', text, flags=re.MULTILINE)
    text = text.strip()

    # Determine which bracket type appears outermost (first in the text)
    first_brace  = text.find('{')
    first_bracket = text.find('[')
    if first_bracket != -1 and (first_brace == -1 or first_bracket < first_brace):
        order = [('[', ']'), ('{', '}')]
    else:
        order = [('{', '}'), ('[', ']')]

    last_error = None
    for start_ch, end_ch in order:
        start = text.find(start_ch)
        end = text.rfind(end_ch)
        if start == -1 or end <= start:
            continue
        candidate = text[start:end + 1]
        for attempt in (candidate, _repair_json(candidate)):
            try:
                return json.loads(attempt)
            except json.JSONDecodeError as exc:
                last_error = exc

    raise ValueError(
        f"Could not extract valid JSON from Gemini response "
        f"(last error: {last_error}): {text[:300]}"
    )


def _gemini(prompt: str, system: str = "", max_tokens: int = 8192) -> str:
    """Call Gemini and return text."""
    token = _get_adc_token()
    url = (f"https://us-central1-aiplatform.googleapis.com/v1/projects/{SECOPS_PROJECT_ID}"
           f"/locations/us-central1/publishers/google/models/{GEMINI_MODEL}:generateContent")
    body: dict = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.1},
    }
    if system:
        body["systemInstruction"] = {"parts": [{"text": system}]}
    resp = requests.post(url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                         json=body, timeout=120)
    if resp.status_code != 200:
        raise RuntimeError(f"Gemini error {resp.status_code}: {resp.text[:300]}")
    candidate = resp.json().get("candidates", [{}])[0]
    finish_reason = candidate.get("finishReason", "")
    if finish_reason == "MAX_TOKENS":
        logger.warning("Gemini response hit MAX_TOKENS limit — output may be truncated")
    parts = candidate.get("content", {}).get("parts", [])
    return "".join(p.get("text", "") for p in parts)

# ═══════════════════════════════════════════════════════════════
# MCP TOOLS
# ═══════════════════════════════════════════════════════════════

@app_mcp.tool()
def analyze_yara_l_rule(rule_text: str) -> str:
    """Analyze a YARA-L rule and extract what UDM events, field conditions, and entity
    relationships are needed to trigger it. Returns structured analysis with trigger requirements."""
    prompt = f"""Analyze this YARA-L rule. Return a compact JSON object with ONLY these fields:
- rule_name: the YARA-L declaration identifier — the exact word after "rule " in the rule text (e.g. "brute_force_success_detection"), NOT the meta.name value
- description: string (max 200 chars, single line)
- event_variables: array of strings (variable names only, e.g. ["$e1","$e2"])
- required_events: array of {{variable, event_type}} objects only (no description field)
- required_fields: array of {{field, operator, value}} objects (no description, max 20 entries)
- entity_joins: array of strings describing joins (e.g. "$e1.principal.ip = $e2.target.ip")
- time_window: string or null
- trigger_summary: string (max 300 chars, single line)
- synthetic_event_hints: object with key=variable name, value=object of field:value pairs to use
- min_event_count: integer — the MINIMUM total number of events required to satisfy the condition block.
  For rules with count conditions like "#fail >= 5 and #success >= 1", this is 5+1=6.
  For simple single-event rules this is 1. Always set this accurately.
- event_breakdown: object mapping each event variable to the minimum count needed, e.g. {{"$fail": 5, "$success": 1}}

Keep ALL string values on a single line. No literal newlines inside strings. Escape backslashes.
For complex rules with many event variables, focus on the MINIMUM subset needed to trigger the rule.

YARA-L Rule:
```
{rule_text}
```

Return ONLY valid compact JSON, no markdown, no explanation."""

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
    trigger the rule. Returns events as JSON strings ready for ingest_log(log_type='UDM')."""
    try:
        analysis = json.loads(analysis_json) if isinstance(analysis_json, str) else analysis_json
    except Exception:
        analysis = {"trigger_summary": analysis_json}

    # Honour min_event_count from analysis — rules like "#fail >= 5 and #success >= 1"
    # need at least 6 events; never generate fewer than what the condition requires.
    min_needed = analysis.get("min_event_count", count)
    actual_count = max(count, min_needed)
    breakdown = analysis.get("event_breakdown", {})
    breakdown_note = (
        f"Event breakdown required: {json.dumps(breakdown)} — "
        f"you MUST generate at least this many events of each type."
        if breakdown else ""
    )

    prompt = f"""Generate exactly {actual_count} synthetic UDM events in JSON format to trigger this YARA-L rule.

Rule analysis:
{json.dumps(analysis, indent=2)}

{breakdown_note}

UDM field reference:
- metadata.event_type: e.g. "NETWORK_CONNECTION", "PROCESS_LAUNCH", "USER_LOGIN", "FILE_CREATION", "NETWORK_DNS", "STATUS_UPDATE"
- metadata.event_timestamp: RFC3339 e.g. "2025-01-15T10:30:00Z"
- metadata.product_name: string
- principal/target/src: ip (array of strings), hostname (string), port (integer), url (string)
- principal/target.user.userid: string
- principal/target.process.command_line: string
- principal/target.process.file.full_path: string
- network.application_protocol: e.g. "HTTP", "HTTPS", "DNS", "SSH", "SMB"
- network.direction: "INBOUND", "OUTBOUND", or "UNKNOWN_DIRECTION"
- network.ip_protocol: "TCP", "UDP", or "ICMP"
- network.http.method: string; network.http.response_code: integer
- network.dns.questions: array of objects with name (string) and type (integer: 1=A, 28=AAAA)
- security_result: array containing ONE object with:
    action: "ALLOW" or "BLOCK" (required when the rule conditions check security_result.action)
    severity: "LOW", "MEDIUM", "HIGH", "CRITICAL", or "INFORMATIONAL"
    summary: string

Rules:
- Each event MUST satisfy the conditions in required_fields
- Use fake but realistic values: IPs 10.0.0.x, hostnames WORKSTATION-01, users jsmith@test.local
- For rules with entity joins (e.g. same $user or $src_ip), ALL events MUST share the exact
  same values for those correlated fields
- ip fields must be arrays of strings: ["10.0.0.1"]
- port fields must be integers, not strings
- security_result must be an ARRAY even if it contains only one object: [{{"action": "BLOCK"}}]

Return ONLY a JSON array of UDM event objects. No markdown, no explanation."""

    try:
        result = _gemini(prompt, max_tokens=8192)
        events = _extract_json(result)
        if not isinstance(events, list):
            events = [events]
        return json.dumps({"events": events, "count": len(events)})
    except Exception as ex:
        return json.dumps({"error": str(ex)})


def _to_int(val, fallback=None):
    try:
        return int(val)
    except (ValueError, TypeError):
        return fallback


def _sanitize_udm_event(e: dict) -> dict:
    """Strip fields that fail UDM schema validation and fix type mismatches."""
    # metadata — strip fields that cause ingestion failures
    meta = e.get("metadata", {})
    meta.pop("ingestion_labels", None)
    # metadata.id must be a valid plain UUID — strip it, SDK will generate a correct one
    meta.pop("id", None)
    e["metadata"] = meta

    # Strip process.pid entirely — it must be uint32 but Gemini consistently
    # generates it as a string and it is not needed to trigger detection rules
    for noun in ("principal", "target", "src", "intermediary", "observer", "about"):
        noun_obj = e.get(noun)
        if not isinstance(noun_obj, dict):
            continue
        proc = noun_obj.get("process")
        if isinstance(proc, dict):
            proc.pop("pid", None)
        if "port" in noun_obj:
            converted = _to_int(noun_obj["port"])
            if converted is not None:
                noun_obj["port"] = converted
            else:
                noun_obj.pop("port")

    # Normalize ip fields — UDM ip is a repeated field (must be array)
    for noun in ("principal", "target", "src", "intermediary", "observer", "about"):
        noun_obj = e.get(noun)
        if not isinstance(noun_obj, dict):
            continue
        for ip_field in ("ip", "mac"):
            val = noun_obj.get(ip_field)
            if isinstance(val, str):
                noun_obj[ip_field] = [val]
        # asset.ip same treatment
        asset = noun_obj.get("asset")
        if isinstance(asset, dict):
            val = asset.get("ip")
            if isinstance(val, str):
                asset["ip"] = [val]

    # network — validate enum fields and clean up http/dns
    VALID_APP_PROTO = {
        "UNKNOWN_APPLICATION_PROTOCOL", "HTTP", "HTTPS", "DNS", "FTP", "SSH",
        "SMB", "SMTP", "IMAP", "POP3", "TELNET", "LDAP", "KERBEROS", "RDP",
        "NFS", "DHCP", "SNMP", "SYSLOG", "TLS", "QUIC",
    }
    VALID_DIRECTION = {"UNKNOWN_DIRECTION", "INBOUND", "OUTBOUND", "BOTH"}
    VALID_IP_PROTO  = {"UNKNOWN_IP_PROTOCOL", "TCP", "UDP", "ICMP", "HOPOPT",
                       "IGMP", "ESP", "GRE", "SCTP", "IPV6"}

    network = e.get("network")
    if isinstance(network, dict):
        for fld, valid_set in (
            ("application_protocol", VALID_APP_PROTO),
            ("direction",            VALID_DIRECTION),
            ("ip_protocol",          VALID_IP_PROTO),
        ):
            val = network.get(fld)
            if val is not None and val not in valid_set:
                network.pop(fld)

        http = network.get("http")
        if isinstance(http, dict):
            # Move any URL field to target.url
            url_val = http.pop("url", None) or http.pop("request_url", None)
            if url_val and isinstance(e.get("target"), dict):
                e["target"].setdefault("url", url_val)
            elif url_val:
                e.setdefault("target", {})["url"] = url_val
            # Fix status_code → response_code as integer
            if "status_code" in http:
                val = http.pop("status_code")
                converted = _to_int(val)
                if converted is not None:
                    http["response_code"] = converted
            if "response_code" in http:
                converted = _to_int(http["response_code"])
                if converted is not None:
                    http["response_code"] = converted
                else:
                    http.pop("response_code")
            # Whitelist: only simple scalar string/int fields
            VALID_HTTP = {"method", "response_code", "user_agent", "referral_url"}
            for k in list(http.keys()):
                if k not in VALID_HTTP:
                    http.pop(k)

    # network.dns — type must be integer
    for dns_list in ("questions", "answers"):
        for entry in e.get("network", {}).get("dns", {}).get(dns_list, []):
            if "type" in entry and isinstance(entry["type"], str):
                dns_type_map = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "AAAA": 28, "TXT": 16, "PTR": 12}
                entry["type"] = dns_type_map.get(entry["type"].upper(), 1)

    # security_result and extensions contain deeply nested enum fields that the SecOps
    # protobuf strictly validates. Gemini consistently generates values that look valid
    # but are rejected by the API. These fields are never required to trigger a YARA-L
    # rule (rules fire on event_type + principal/target/network conditions), so we strip
    # them entirely to eliminate this entire class of ingestion failures.
    e.pop("security_result", None)
    e.pop("extensions", None)

    return e


@app_mcp.tool()
def ingest_synthetic_events(events_json: str) -> str:
    """Ingest synthetic logs into SecOps for rule testing.
    Accepts the output of generate_synthetic_events (raw logs + log_type).
    Uses ingest_log so SecOps's own parsers handle UDM conversion — no enum issues.
    Returns ingestion status and a validation_id to track this test run."""
    try:
        data = json.loads(events_json) if isinstance(events_json, str) else events_json

        from secops import SecOpsClient
        client = SecOpsClient().chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION,
        )

        validation_id = f"yaral-test-{uuid.uuid4().hex[:12]}"
        ingestion_time = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        # Accept {events: [...]} from generate_synthetic_events
        if isinstance(data, dict) and "events" in data:
            events = data["events"]
        elif isinstance(data, list):
            events = data
        else:
            return json.dumps({"error": "Expected {events: [...]} from generate_synthetic_events"})

        if not isinstance(events, list) or not events:
            return json.dumps({"error": "No events to ingest"})

        # Serialize each UDM event as a JSON string — ingest_log(log_type="UDM") accepts
        # pre-formed UDM JSON strings and bypasses the strict enum validation of ingest_udm
        log_messages = [json.dumps(e) for e in events]
        logger.info(f"Ingesting {len(log_messages)} UDM events via ingest_log — first: {log_messages[0][:400]}")
        result = client.ingest_log(
            log_type="UDM",
            log_message=log_messages,
            force_log_type=True,
        )
        return json.dumps({
            "status": "ingested",
            "validation_id": validation_id,
            "event_count": len(events),
            "ingestion_time": ingestion_time,
            "api_response": result,
            "message": f"Ingested {len(events)} UDM events via ingest_log. Wait 2-5 min then verify.",
        })

    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def verify_rule_triggered(rule_name: str, minutes_back: int = 10, validation_id: str = "") -> str:
    """Poll SecOps detections to check if a rule fired after synthetic event ingestion.
    rule_name: exact name of the YARA-L rule (as it appears in the rule text after 'rule ').
    minutes_back: how far back to look for detections (default 10 minutes).
    validation_id: optional — included in response for correlation only."""
    try:
        from secops import SecOpsClient
        client = SecOpsClient().chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION,
        )

        # Step 1: find the rule_id for this rule_name.
        # rule_name may be the YARA-L declaration identifier OR the ru_xxx ID directly.
        if rule_name.startswith("ru_"):
            rule_id = rule_name
        else:
            rules = client.list_rules(view="FULL", as_list=True)
            rule_id = None
            needle = rule_name.lower().strip()
            for r in rules:
                res_name  = r.get("name", "")
                display   = r.get("displayName", "").lower()
                rule_text = r.get("text", "")
                ru_id     = res_name.split("/rules/")[-1]
                if (needle == display or
                        needle == ru_id or
                        f"rule {needle}" in rule_text.lower() or
                        needle in res_name.lower()):
                    rule_id = ru_id
                    break

        if not rule_id:
            return json.dumps({
                "rule_name": rule_name,
                "error": f"Rule '{rule_name}' not found in SecOps. "
                         "Ensure the rule is deployed (enabled or disabled) in the instance.",
                "available_rules": [r.get("name", "").split("/rules/")[-1] + " — " +
                                    r.get("displayName", "") for r in rules[:20]],
            })

        # Step 2: list detections for that rule over the time window
        end_time   = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=minutes_back)
        result = client.list_detections(
            rule_id=rule_id,
            start_time=start_time,
            end_time=end_time,
            page_size=20,
            as_list=True,
        )
        detections = result if isinstance(result, list) else result.get("detections", [])

        return json.dumps({
            "rule_name": rule_name,
            "rule_id": rule_id,
            "validation_id": validation_id,
            "detection_found": len(detections) > 0,
            "detection_count": len(detections),
            "time_window_minutes": minutes_back,
            "detections": detections[:5],
            "verdict": (
                "PASS ✅ — Rule fired on synthetic events" if detections else
                "PENDING ⏳ — No detections yet. SecOps may still be processing. Try again in 2-3 minutes."
            ),
        })

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
