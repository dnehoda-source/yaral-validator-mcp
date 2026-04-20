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
    """Given the output of analyze_yara_l_rule, generate synthetic UDM events that trigger
    the rule when ingested via ingest_udm. Returns {events: [...], count: N}."""
    try:
        analysis = json.loads(analysis_json) if isinstance(analysis_json, str) else analysis_json
    except Exception:
        analysis = {"trigger_summary": analysis_json}

    min_needed   = analysis.get("min_event_count", count)
    actual_count = max(count, min_needed)
    breakdown    = analysis.get("event_breakdown", {})

    # Current timestamps spread across a 9-minute window so LIVE rules evaluate them
    now = datetime.now(timezone.utc)
    timestamps = [
        (now + timedelta(minutes=i)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        for i in range(actual_count)
    ]

    prompt = f"""Generate {actual_count} synthetic UDM event objects that will trigger this YARA-L rule.

Rule analysis:
{json.dumps(analysis, indent=2)}

Event breakdown needed: {json.dumps(breakdown) if breakdown else "see condition block"}
Use THESE exact timestamps (current UTC time — live rules will evaluate them):
{json.dumps(timestamps)}

Rules for generating valid UDM events:
- metadata.event_type must be a valid UDM enum string: USER_LOGIN, NETWORK_CONNECTION, PROCESS_LAUNCH, NETWORK_HTTP, FILE_CREATION, USER_RESOURCE_ACCESS
- metadata.event_timestamp: use the timestamps above, one per event
- metadata.product_name: use "synthetic-test"
- principal.ip and target.ip must be JSON arrays of strings: ["10.0.0.5"]
- principal.user.userid and target.user.userid: plain strings like "jsmith@corp.local"
- security_result must be a JSON array; security_result[0].action must be a JSON array with ONE of: "ALLOW", "BLOCK"
- Do NOT include: process.pid (causes type errors), extensions, ingestion_labels, metadata.id
- For correlated rules (same user across events): use identical principal.user.userid and principal.ip across all events

Return ONLY this JSON, no markdown:
{{
  "events": [
    {{
      "metadata": {{"event_timestamp": "TIMESTAMP_0", "event_type": "USER_LOGIN", "product_name": "synthetic-test"}},
      "principal": {{"ip": ["10.0.0.5"], "user": {{"userid": "jsmith@corp.local"}}}},
      "target": {{"application": "vpn", "user": {{"userid": "jsmith@corp.local"}}}},
      "security_result": [{{"action": ["BLOCK"]}}]
    }},
    ...{actual_count - 1} more events...
  ]
}}

Example for brute-force (5 BLOCK + 1 ALLOW, same user):
- events 1-5: security_result=[{{"action":["BLOCK"]}}], same user/IP
- event 6:    security_result=[{{"action":["ALLOW"]}}], same user/IP"""

    try:
        result = _gemini(prompt, max_tokens=8192)
        parsed = _extract_json(result)
        if isinstance(parsed, dict) and "events" in parsed:
            events = parsed["events"] if isinstance(parsed["events"], list) else [parsed["events"]]
            return json.dumps({"events": events, "count": len(events)})
        return json.dumps({"error": f"Generator returned unexpected format: {result[:200]}"})
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

    # security_result — keep only action field with valid enum values; strip all else.
    # extensions — strip entirely (deeply nested enums not needed to trigger rules).
    VALID_SR_ACTIONS = {"UNKNOWN_ACTION", "ALLOW", "BLOCK", "QUARANTINE", "UNKNOWN_VERDICT"}
    ACTION_MAP = {
        "SUCCESS": "ALLOW", "ALLOWED": "ALLOW", "PASS": "ALLOW", "PERMIT": "ALLOW",
        "FAILURE": "BLOCK", "FAIL": "BLOCK", "DENY": "BLOCK", "DENIED": "BLOCK",
        "BLOCKED": "BLOCK", "REJECT": "BLOCK", "REJECTED": "BLOCK",
    }
    sr = e.get("security_result")
    if isinstance(sr, list):
        cleaned_sr = []
        for item in sr:
            if not isinstance(item, dict):
                continue
            action = item.get("action")
            if isinstance(action, list):
                valid_actions = [
                    ACTION_MAP.get(str(a).upper(), str(a))
                    for a in action
                    if ACTION_MAP.get(str(a).upper(), str(a)) in VALID_SR_ACTIONS
                ]
                if valid_actions:
                    cleaned_sr.append({"action": valid_actions})
            elif isinstance(action, str):
                mapped = ACTION_MAP.get(action.upper(), action)
                if mapped in VALID_SR_ACTIONS:
                    cleaned_sr.append({"action": [mapped]})
        if cleaned_sr:
            e["security_result"] = cleaned_sr
        else:
            e.pop("security_result", None)
    elif isinstance(sr, dict):
        action = sr.get("action")
        if isinstance(action, str):
            mapped = ACTION_MAP.get(action.upper(), action)
            if mapped in VALID_SR_ACTIONS:
                e["security_result"] = [{"action": [mapped]}]
            else:
                e.pop("security_result", None)
        else:
            e.pop("security_result", None)
    e.pop("extensions", None)

    return e


@app_mcp.tool()
def ingest_synthetic_events(events_json: str) -> str:
    """Ingest synthetic UDM events directly into SecOps via events:import (no parser delay).
    Accepts the output of generate_synthetic_events ({events: [...]}).
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

        if isinstance(data, dict) and "events" in data:
            events = data["events"]
            if not isinstance(events, list):
                events = [events]

            sanitized = [_sanitize_udm_event(e) for e in events]
            logger.info(f"Ingesting {len(sanitized)} UDM events via ingest_udm — first: {str(sanitized[0])[:300]}")

            result = client.ingest_udm(sanitized)
            return json.dumps({
                "status": "ingested",
                "validation_id": validation_id,
                "method": "ingest_udm",
                "event_count": len(sanitized),
                "ingestion_time": ingestion_time,
                "api_response": result,
                "message": f"Ingested {len(sanitized)} UDM events directly. No parser delay — rule evaluation is near-immediate.",
            })

        return json.dumps({"error": "Expected {events: [...]} output from generate_synthetic_events"})

    except Exception as e:
        return json.dumps({"error": str(e)})


def _find_rule_id(client, rule_name: str) -> str | None:
    """Return the ru_xxx ID for a rule matching rule_name, or None."""
    if rule_name.startswith("ru_"):
        return rule_name
    rules = client.list_rules(view="FULL", as_list=True)
    needle = rule_name.lower().strip()
    for r in rules:
        res_name  = r.get("name", "")
        display   = r.get("displayName", "").lower()
        rule_text = r.get("text", "")
        ru_id     = res_name.split("/rules/")[-1]
        if needle == display or needle == ru_id or f"rule {needle}" in rule_text.lower():
            return ru_id
    return None


@app_mcp.tool()
def ensure_rule_live(rule_name: str) -> str:
    """Ensure a YARA-L rule is enabled and running at LIVE (near-real-time) frequency.
    Call this before ingesting synthetic events so detections fire without waiting.
    rule_name: YARA-L declaration name or ru_xxx ID."""
    try:
        from secops import SecOpsClient
        client = SecOpsClient().chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION,
        )
        rule_id = _find_rule_id(client, rule_name)
        if not rule_id:
            return json.dumps({"error": f"Rule '{rule_name}' not found in SecOps instance."})

        deployment = client.get_rule_deployment(rule_id)
        already_enabled = deployment.get("enabled", False)
        already_live    = deployment.get("runFrequency", "") == "LIVE"

        if already_enabled and already_live:
            return json.dumps({
                "rule_name": rule_name,
                "rule_id": rule_id,
                "status": "already_live",
                "enabled": True,
                "run_frequency": "LIVE",
                "message": "Rule is already enabled and running LIVE — ready for validation.",
            })

        result = client.update_rule_deployment(rule_id, enabled=True, run_frequency="LIVE")
        return json.dumps({
            "rule_name": rule_name,
            "rule_id": rule_id,
            "status": "enabled",
            "enabled": result.get("enabled"),
            "run_frequency": result.get("runFrequency"),
            "message": "Rule enabled and set to LIVE frequency — detections will fire in near real-time.",
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


def _summarize_detections(detections: list) -> list:
    """Turn raw detection JSON into plain-English summaries the user can read."""
    summaries = []
    for det in detections:
        rule_det = (det.get("detection") or [{}])[0]
        fields = {f.get("key"): f.get("value") for f in rule_det.get("detectionFields", [])}
        user = fields.get("user") or fields.get("principal_user") or fields.get("username") or "unknown user"
        src  = fields.get("src_ip") or fields.get("source_ip") or fields.get("ip") or "unknown IP"
        host = fields.get("hostname") or fields.get("host") or ""
        severity = rule_det.get("severity", "")
        rule_n   = rule_det.get("ruleName", "")

        # Group collectionElements by label
        groups = {}
        for elem in det.get("collectionElements", []):
            label = elem.get("label", "events")
            times = []
            for ref in elem.get("references", []):
                ts = ref.get("event", {}).get("metadata", {}).get("eventTimestamp", "")
                if ts:
                    times.append(ts)
            if times:
                groups[label] = sorted(times)

        parts = []
        fail_times    = groups.get("fail") or groups.get("failed") or groups.get("failure")
        success_times = groups.get("success") or groups.get("successful") or groups.get("allowed")

        if fail_times and success_times:
            fstart = fail_times[0][11:19]
            fend   = fail_times[-1][11:19]
            sstart = success_times[0][11:19]
            parts.append(
                f"{user} from {src}{' on ' + host if host else ''} failed {len(fail_times)} "
                f"login attempts between {fstart} and {fend} UTC, then successfully "
                f"logged in at {sstart} UTC."
            )
        else:
            total_events = sum(len(t) for t in groups.values())
            first = min((t[0] for t in groups.values() if t), default="")
            last  = max((t[-1] for t in groups.values() if t), default="")
            if total_events and first and last:
                parts.append(
                    f"{user} from {src}{' on ' + host if host else ''} "
                    f"triggered {total_events} correlated events between "
                    f"{first[11:19]} and {last[11:19]} UTC."
                )
            else:
                parts.append(f"{user} from {src} triggered rule {rule_n}.")

        headline = f"🚨 [{severity}] Detection fired on rule `{rule_n}`" if severity else f"🚨 Detection fired on rule `{rule_n}`"
        summaries.append(f"{headline}\n{parts[0]}")
    return summaries


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

        rule_id = _find_rule_id(client, rule_name)
        if not rule_id:
            return json.dumps({
                "rule_name": rule_name,
                "error": f"Rule '{rule_name}' not found in SecOps. Ensure the rule is deployed.",
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

        summaries = _summarize_detections(detections) if detections else []

        return json.dumps({
            "rule_name": rule_name,
            "rule_id": rule_id,
            "validation_id": validation_id,
            "detection_found": len(detections) > 0,
            "detection_count": len(detections),
            "time_window_minutes": minutes_back,
            "summary": summaries,
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
        min_count = analysis.get("min_event_count", 5)
        events_raw = generate_synthetic_events(analysis_raw, count=max(5, min_count))
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
# NEGATIVE TESTING — prove the rule is not over-broad
# ═══════════════════════════════════════════════════════════════

@app_mcp.tool()
def generate_negative_events(analysis_json: str, count: int = 3) -> str:
    """Generate near-miss UDM events that should NOT trigger the rule. Each variant perturbs
    ONE axis of the rule's conditions so the rule stays quiet. Used for false-positive testing."""
    try:
        analysis = json.loads(analysis_json) if isinstance(analysis_json, str) else analysis_json
    except Exception:
        analysis = {"trigger_summary": analysis_json}

    breakdown = analysis.get("event_breakdown", {})
    now = datetime.now(timezone.utc)
    timestamps = [
        (now + timedelta(minutes=i)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        for i in range(10)
    ]

    prompt = f"""Generate synthetic UDM events that LOOK like the attacker pattern but FAIL to trigger this rule.
Each scenario must perturb exactly ONE axis so the rule stays silent — this proves the rule is not over-broad.

Rule analysis:
{json.dumps(analysis, indent=2)}

Event breakdown: {json.dumps(breakdown) if breakdown else "see condition block"}
Available timestamps: {json.dumps(timestamps)}

Generate {count} distinct scenarios. Each scenario is a list of UDM events that violate ONE of these:
- Threshold just below trigger (e.g. rule needs #fail>=5, generate 4 fails + 1 success)
- Different entity (e.g. same user but different IP, or different user but same IP — breaks correlation)
- Outside time window (e.g. events spaced 2h apart when window is 10m)
- Wrong action value (e.g. ALLOW instead of BLOCK)
- Missing required event type (e.g. 5 fails but NO success)

Each event must be a valid UDM dict with:
- metadata.event_timestamp, metadata.event_type, metadata.product_name="synthetic-test"
- principal.ip as JSON array, principal.user.userid
- target.application, target.user.userid
- security_result[0].action as JSON array with ALLOW or BLOCK
- NO process.pid, NO extensions, NO ingestion_labels

Return ONLY this JSON, no markdown:
{{
  "scenarios": [
    {{
      "name": "threshold_minus_one",
      "perturbation": "4 failed logins + 1 success (rule needs >=5 failed)",
      "expected": "NO DETECTION",
      "events": [...]
    }},
    {{
      "name": "different_ip_break_correlation",
      "perturbation": "5 failed logins from 10.0.0.5, success from different IP 10.99.99.99",
      "expected": "NO DETECTION",
      "events": [...]
    }},
    ...
  ]
}}"""

    try:
        result = _gemini(prompt, max_tokens=8192)
        parsed = _extract_json(result)
        if isinstance(parsed, dict) and "scenarios" in parsed:
            return json.dumps({"scenarios": parsed["scenarios"], "count": len(parsed["scenarios"])})
        return json.dumps({"error": f"Generator returned unexpected format: {str(result)[:200]}"})
    except Exception as ex:
        return json.dumps({"error": str(ex)})


@app_mcp.tool()
def ingest_negative_scenario(events_json: str) -> str:
    """Ingest a single negative scenario's events (flat list). Returns ingestion status."""
    try:
        data = json.loads(events_json) if isinstance(events_json, str) else events_json
        if isinstance(data, dict) and "events" in data:
            events = data["events"]
        elif isinstance(data, list):
            events = data
        else:
            return json.dumps({"error": "Expected {events: [...]} or [events]"})

        from secops import SecOpsClient
        client = SecOpsClient().chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION,
        )
        sanitized = [_sanitize_udm_event(e) for e in events]
        validation_id = f"yaral-neg-{uuid.uuid4().hex[:12]}"
        result = client.ingest_udm(sanitized)
        return json.dumps({
            "status": "ingested",
            "validation_id": validation_id,
            "event_count": len(sanitized),
            "ingestion_time": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            "api_response": result,
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def verify_rule_quiet(rule_name: str, minutes_back: int = 5, validation_id: str = "") -> str:
    """Inverse of verify_rule_triggered: confirms the rule did NOT fire in the window.
    Used for negative-test scenarios where rule firing = FAILURE (over-broad rule)."""
    try:
        raw = verify_rule_triggered(rule_name, minutes_back=minutes_back, validation_id=validation_id)
        data = json.loads(raw)
        if "error" in data:
            return raw
        triggered = data.get("detection_found", False)
        return json.dumps({
            "rule_name": rule_name,
            "validation_id": validation_id,
            "triggered": triggered,
            "detection_count": data.get("detection_count", 0),
            "verdict": (
                "FAIL ❌ — Rule fired on benign events (over-broad)" if triggered else
                "PASS ✅ — Rule stayed quiet on near-miss events"
            ),
            "negative_pass": not triggered,
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# FIXTURE CACHING — save/replay successful event sets
# ═══════════════════════════════════════════════════════════════

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _sanitize_fixture_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_\-]", "_", name)[:100] or "unnamed"


def _reset_timestamps(events: list) -> list:
    """Rewrite event timestamps to be current (spread 1 minute apart)."""
    now = datetime.now(timezone.utc)
    out = []
    for i, e in enumerate(events):
        e = json.loads(json.dumps(e))  # deep copy
        meta = e.setdefault("metadata", {})
        meta["event_timestamp"] = (now + timedelta(minutes=i)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        meta.pop("id", None)
        out.append(e)
    return out


@app_mcp.tool()
def save_fixture(rule_name: str, events_json: str, metadata_json: str = "") -> str:
    """Save the events that successfully validated a rule as a reusable fixture.
    Fixture is keyed by rule_name and stored at fixtures/<rule_name>.json."""
    try:
        os.makedirs(FIXTURE_DIR, exist_ok=True)
        events_data = json.loads(events_json) if isinstance(events_json, str) else events_json
        events = events_data.get("events", events_data) if isinstance(events_data, dict) else events_data
        meta = json.loads(metadata_json) if metadata_json else {}

        name = _sanitize_fixture_name(rule_name)
        path = os.path.join(FIXTURE_DIR, f"{name}.json")
        fixture = {
            "rule_name": rule_name,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "event_count": len(events),
            "events": events,
            "metadata": meta,
        }
        with open(path, "w") as f:
            json.dump(fixture, f, indent=2)
        return json.dumps({"status": "saved", "path": path, "rule_name": rule_name, "event_count": len(events)})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def load_fixture(rule_name: str, refresh_timestamps: bool = True) -> str:
    """Load a saved fixture for replay. If refresh_timestamps=True, rewrites timestamps to now
    so LIVE rules evaluate the events."""
    try:
        name = _sanitize_fixture_name(rule_name)
        path = os.path.join(FIXTURE_DIR, f"{name}.json")
        if not os.path.exists(path):
            return json.dumps({"error": f"No fixture for '{rule_name}' at {path}"})
        with open(path) as f:
            fixture = json.load(f)
        events = fixture.get("events", [])
        if refresh_timestamps:
            events = _reset_timestamps(events)
        return json.dumps({
            "status": "loaded",
            "rule_name": fixture.get("rule_name", rule_name),
            "saved_at": fixture.get("saved_at", ""),
            "event_count": len(events),
            "events": events,
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def list_fixtures() -> str:
    """List all saved fixtures and their metadata."""
    try:
        if not os.path.isdir(FIXTURE_DIR):
            return json.dumps({"fixtures": []})
        items = []
        for fn in sorted(os.listdir(FIXTURE_DIR)):
            if not fn.endswith(".json"):
                continue
            try:
                with open(os.path.join(FIXTURE_DIR, fn)) as f:
                    d = json.load(f)
                items.append({
                    "file": fn,
                    "rule_name": d.get("rule_name", fn[:-5]),
                    "saved_at": d.get("saved_at", ""),
                    "event_count": d.get("event_count", len(d.get("events", []))),
                })
            except Exception:
                continue
        return json.dumps({"fixtures": items, "count": len(items)})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# BATCH VALIDATION — run pipeline across many rules
# ═══════════════════════════════════════════════════════════════

@app_mcp.tool()
def batch_validate(rules_json: str, use_fixtures: bool = True, run_negative: bool = False) -> str:
    """Validate multiple YARA-L rules in one pass. Returns pass/fail matrix.
    rules_json: JSON array of {name, rule_text} entries.
    use_fixtures: if True, replay cached fixtures when available instead of regenerating.
    run_negative: if True, also run negative testing for each rule.
    NOTE: This only does analyze + generate + ingest. Polling verify is done client-side."""
    try:
        rules = json.loads(rules_json) if isinstance(rules_json, str) else rules_json
        if not isinstance(rules, list):
            return json.dumps({"error": "Expected a JSON array of rules"})

        results = []
        for rule in rules:
            name = rule.get("name", "")
            rule_text = rule.get("rule_text", rule.get("text", ""))
            if not rule_text:
                results.append({"rule_name": name, "status": "skipped", "reason": "no rule_text"})
                continue

            entry = {"rule_name": name, "stages": {}}
            try:
                analysis_raw = analyze_yara_l_rule(rule_text)
                analysis = json.loads(analysis_raw)
                if "error" in analysis:
                    entry["stages"]["analyze"] = {"status": "fail", "error": analysis["error"]}
                    entry["status"] = "fail"
                    results.append(entry)
                    continue
                entry["stages"]["analyze"] = {"status": "pass"}
                resolved_name = analysis.get("rule_name", name)

                fixture_data = None
                if use_fixtures:
                    fl = json.loads(load_fixture(resolved_name))
                    if "events" in fl and "error" not in fl:
                        fixture_data = fl
                        entry["stages"]["fixture"] = {"status": "loaded", "event_count": fl["event_count"]}

                if fixture_data:
                    events_payload = {"events": fixture_data["events"]}
                else:
                    min_count = analysis.get("min_event_count", 5)
                    gen_raw = generate_synthetic_events(analysis_raw, count=max(5, min_count))
                    gen = json.loads(gen_raw)
                    if "error" in gen:
                        entry["stages"]["generate"] = {"status": "fail", "error": gen["error"]}
                        entry["status"] = "fail"
                        results.append(entry)
                        continue
                    events_payload = gen
                    entry["stages"]["generate"] = {"status": "pass", "event_count": gen.get("count", 0)}

                ingest_raw = ingest_synthetic_events(json.dumps(events_payload))
                ingest = json.loads(ingest_raw)
                if "error" in ingest:
                    entry["stages"]["ingest"] = {"status": "fail", "error": ingest["error"]}
                    entry["status"] = "fail"
                    results.append(entry)
                    continue
                entry["stages"]["ingest"] = {"status": "pass", "validation_id": ingest.get("validation_id")}
                entry["validation_id"] = ingest.get("validation_id")
                entry["rule_name_resolved"] = resolved_name

                if run_negative:
                    neg_raw = generate_negative_events(analysis_raw, count=2)
                    neg = json.loads(neg_raw)
                    if "scenarios" in neg:
                        entry["stages"]["negative_generate"] = {"status": "pass", "scenarios": len(neg["scenarios"])}
                        entry["negative_scenarios"] = neg["scenarios"]

                entry["status"] = "ingested_awaiting_verify"
            except Exception as e:
                entry["stages"]["error"] = str(e)
                entry["status"] = "error"
            results.append(entry)

        summary = {
            "total": len(results),
            "ingested": sum(1 for r in results if r.get("status") == "ingested_awaiting_verify"),
            "failed": sum(1 for r in results if r.get("status") in ("fail", "error")),
            "skipped": sum(1 for r in results if r.get("status") == "skipped"),
        }
        return json.dumps({"summary": summary, "results": results})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# COMPOSITE DETECTION — chain base rules → composite rule
# ═══════════════════════════════════════════════════════════════

COMPOSITE_MARKERS = [
    r"\bdetection\b",
    r"\boutcome\b",
    r"\bgraph\b",
    r"%\w+\.",
]


def _detect_composite(rule_text: str) -> dict:
    """Heuristic: does this rule reference other rules' outcomes or multi-event joins?"""
    has_detection_ref   = bool(re.search(r"\.detection\.", rule_text))
    has_rule_ref        = bool(re.search(r"rule\s*=\s*\"[^\"]+\"", rule_text))
    match_vars          = re.findall(r"\$\w+", rule_text)
    distinct_vars       = len(set(match_vars))
    has_multi_events    = distinct_vars >= 3
    is_composite        = has_detection_ref or has_rule_ref or has_multi_events
    return {
        "is_composite": is_composite,
        "has_detection_ref": has_detection_ref,
        "has_rule_ref": has_rule_ref,
        "distinct_event_vars": distinct_vars,
        "has_multi_events": has_multi_events,
    }


@app_mcp.tool()
def analyze_composite_rule(rule_text: str) -> str:
    """Analyze a composite YARA-L rule: extract base rule dependencies, entity join keys,
    ordering constraints, and the cascade the rule expects."""
    heuristic = _detect_composite(rule_text)
    prompt = f"""Analyze this YARA-L rule as a potentially COMPOSITE detection (chains multiple base detections or
multiple event types on the same entity). Return compact JSON with ONLY these fields:
- rule_name: YARA-L identifier after "rule "
- is_composite: boolean (true if it requires multiple rule firings or 3+ correlated event types)
- composite_kind: "chained_rules" | "multi_event_correlation" | "entity_join" | "none"
- base_components: array of {{stage_name, event_type, security_result_action, description}}
   — one entry per stage/base event set the composite needs. For chained rules, each base detection.
   For multi-event correlation, each distinct event variable.
- join_keys: array of strings (e.g. ["principal.user.userid", "principal.ip"]) — the entity fields
   that must match across all stages.
- ordering: "sequential" | "any_order" | null — do the stages need to fire in order?
- time_window: string or null (e.g. "1h", "10m")
- cascade_description: string — one sentence describing the full attack chain the rule catches.

Return ONLY valid compact JSON.

YARA-L Rule:
```
{rule_text}
```"""
    try:
        result = _gemini(prompt, max_tokens=4096)
        parsed = _extract_json(result)
        parsed["heuristic"] = heuristic
        parsed["raw_rule"] = rule_text
        return json.dumps(parsed, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "heuristic": heuristic})


@app_mcp.tool()
def generate_cascade_events(composite_analysis_json: str) -> str:
    """Given a composite rule analysis, generate a chained set of UDM events that fire each stage
    in sequence (or any order) with join_keys threaded through all of them.
    Returns {stages: [{stage_name, events}], all_events, count}."""
    try:
        analysis = json.loads(composite_analysis_json) if isinstance(composite_analysis_json, str) else composite_analysis_json
    except Exception:
        return json.dumps({"error": "Invalid composite_analysis_json"})

    stages = analysis.get("base_components", [])
    if not stages:
        return json.dumps({"error": "No base_components in composite analysis"})

    join_keys = analysis.get("join_keys", [])
    ordering  = analysis.get("ordering", "sequential")
    now = datetime.now(timezone.utc)

    prompt = f"""Generate a CASCADE of UDM events that fires a composite detection in sequence.
The composite has {len(stages)} stages; generate 1-3 events per stage.

Composite analysis:
{json.dumps(analysis, indent=2)}

Rules:
- All stages must share the SAME entity values for these join_keys: {json.dumps(join_keys)}
  (e.g. same principal.user.userid and principal.ip across every stage)
- Events across stages must be temporally ordered if ordering="sequential" (stage 1 before stage 2, etc.)
- Use timestamps starting at {now.strftime('%Y-%m-%dT%H:%M:%S.000Z')}, spaced 1-2 minutes apart
- Each event must be a valid UDM dict (same schema as generate_synthetic_events)
- security_result[0].action must be "ALLOW" or "BLOCK"

Return ONLY this JSON, no markdown:
{{
  "stages": [
    {{"stage_name": "stage_1_name", "events": [...UDM events...]}},
    {{"stage_name": "stage_2_name", "events": [...UDM events...]}}
  ]
}}"""
    try:
        result = _gemini(prompt, max_tokens=8192)
        parsed = _extract_json(result)
        if not isinstance(parsed, dict) or "stages" not in parsed:
            return json.dumps({"error": f"Generator returned unexpected format: {str(result)[:200]}"})
        all_events = []
        for stage in parsed["stages"]:
            all_events.extend(stage.get("events", []))
        return json.dumps({
            "stages": parsed["stages"],
            "all_events": all_events,
            "count": len(all_events),
            "stage_count": len(parsed["stages"]),
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def cascade_validate(composite_rule_text: str, base_rule_names: str = "") -> str:
    """End-to-end composite validation: analyze → generate cascade → ingest. Client polls each
    base rule + composite rule to confirm the cascade fires.
    base_rule_names: comma-separated list of base rule names (for client-side cascade polling)."""
    try:
        analysis_raw = analyze_composite_rule(composite_rule_text)
        analysis = json.loads(analysis_raw)
        if "error" in analysis:
            return json.dumps({"status": "FAILED", "stage": "analyze", "analysis": analysis})

        cascade_raw = generate_cascade_events(analysis_raw)
        cascade = json.loads(cascade_raw)
        if "error" in cascade:
            return json.dumps({"status": "FAILED", "stage": "cascade_generate", "cascade": cascade})

        events_payload = {"events": cascade["all_events"]}
        ingest_raw = ingest_synthetic_events(json.dumps(events_payload))
        ingest = json.loads(ingest_raw)
        if "error" in ingest:
            return json.dumps({"status": "FAILED", "stage": "ingest", "ingest": ingest})

        base_rules = [n.strip() for n in base_rule_names.split(",") if n.strip()]
        return json.dumps({
            "status": "INGESTED_AWAITING_CASCADE_VERIFY",
            "composite_rule_name": analysis.get("rule_name", ""),
            "base_rule_names": base_rules,
            "stages": cascade["stages"],
            "stage_count": cascade["stage_count"],
            "event_count": cascade["count"],
            "validation_id": ingest.get("validation_id", ""),
            "analysis": analysis,
            "ingestion_time": ingest.get("ingestion_time", ""),
            "next_step": f"Poll verify_rule_triggered for each of: [{', '.join(base_rules + [analysis.get('rule_name', 'composite')])}] every 30s.",
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


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


@app.post("/api/enable-rule")
async def api_enable_rule(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    rule_name = body.get("rule_name", "")
    if not rule_name:
        return JSONResponse({"error": "rule_name required"}, status_code=400)
    result = ensure_rule_live(rule_name)
    return JSONResponse(json.loads(result))


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


# ── NEGATIVE TESTING ENDPOINTS ─────────────────────────────────
@app.post("/api/generate-negative")
async def api_generate_negative(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    analysis_json = body.get("analysis_json", "")
    count = int(body.get("count", 3))
    if not analysis_json:
        return JSONResponse({"error": "No analysis provided"}, status_code=400)
    result = generate_negative_events(analysis_json, count=count)
    return JSONResponse(json.loads(result))


@app.post("/api/ingest-negative")
async def api_ingest_negative(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    events_json = body.get("events_json", "")
    if not events_json:
        return JSONResponse({"error": "No events provided"}, status_code=400)
    result = ingest_negative_scenario(events_json)
    return JSONResponse(json.loads(result))


@app.post("/api/verify-quiet")
async def api_verify_quiet(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    rule_name = body.get("rule_name", "")
    validation_id = body.get("validation_id", "")
    minutes_back = int(body.get("minutes_back", 5))
    result = verify_rule_quiet(rule_name, minutes_back=minutes_back, validation_id=validation_id)
    return JSONResponse(json.loads(result))


# ── FIXTURE ENDPOINTS ──────────────────────────────────────────
@app.post("/api/fixture/save")
async def api_fixture_save(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    rule_name = body.get("rule_name", "")
    events_json = body.get("events_json", "")
    metadata_json = body.get("metadata_json", "")
    if not rule_name or not events_json:
        return JSONResponse({"error": "rule_name and events_json required"}, status_code=400)
    result = save_fixture(rule_name, events_json, metadata_json)
    return JSONResponse(json.loads(result))


@app.post("/api/fixture/load")
async def api_fixture_load(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    rule_name = body.get("rule_name", "")
    refresh = bool(body.get("refresh_timestamps", True))
    if not rule_name:
        return JSONResponse({"error": "rule_name required"}, status_code=400)
    result = load_fixture(rule_name, refresh_timestamps=refresh)
    return JSONResponse(json.loads(result))


@app.get("/api/fixture/list")
async def api_fixture_list(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    result = list_fixtures()
    return JSONResponse(json.loads(result))


# ── BATCH VALIDATION ENDPOINT ──────────────────────────────────
@app.post("/api/batch-validate")
async def api_batch_validate(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    rules_json = body.get("rules_json", "")
    use_fixtures = bool(body.get("use_fixtures", True))
    run_negative = bool(body.get("run_negative", False))
    if not rules_json:
        return JSONResponse({"error": "rules_json required"}, status_code=400)
    result = batch_validate(rules_json, use_fixtures=use_fixtures, run_negative=run_negative)
    return JSONResponse(json.loads(result))


# ── COMPOSITE DETECTION ENDPOINTS ──────────────────────────────
@app.post("/api/analyze-composite")
async def api_analyze_composite(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    rule_text = body.get("rule_text", body.get("rule", "")).strip()
    if not rule_text:
        return JSONResponse({"error": "rule_text required"}, status_code=400)
    result = analyze_composite_rule(rule_text)
    return JSONResponse(json.loads(result))


@app.post("/api/generate-cascade")
async def api_generate_cascade(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    analysis_json = body.get("analysis_json", "")
    if not analysis_json:
        return JSONResponse({"error": "analysis_json required"}, status_code=400)
    result = generate_cascade_events(analysis_json)
    return JSONResponse(json.loads(result))


@app.post("/api/cascade-validate")
async def api_cascade_validate(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    rule_text = body.get("rule_text", "").strip()
    base_rule_names = body.get("base_rule_names", "")
    if not rule_text:
        return JSONResponse({"error": "rule_text required"}, status_code=400)
    result = cascade_validate(rule_text, base_rule_names)
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
