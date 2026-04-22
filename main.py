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
import hashlib
import logging
import requests
import threading
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


# ── METRICS ──────────────────────────────────────────────────────
class MetricsCollector:
    """In-memory aggregate metrics for the detection-team dashboard.

    Persisted to $METRICS_PATH (default ./metrics.json) on every increment so
    counts survive container restarts. For scale beyond one Cloud Run instance
    point METRICS_PATH at a shared filesystem or swap in a real backend.
    """

    def __init__(self, path: str | None = None):
        self.path = path or os.getenv("METRICS_PATH", "./metrics.json")
        self._lock = threading.Lock()
        self._data = self._load()

    def _load(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {
                "validations_total": 0,
                "by_outcome": {"PASS": 0, "FAIL": 0, "ERROR": 0, "SKIPPED": 0, "AWAITING": 0},
                "composite_static_runs": 0,
                "negative_tests_total": 0,
                "fixture_saves_total": 0,
                "fixture_loads_total": 0,
                "rules_seen": {},
                "last_run": None,
                "first_run": None,
            }

    def _save(self) -> None:
        try:
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2, default=str)
        except Exception as exc:
            logger.warning(f"Could not persist metrics to {self.path}: {exc}")

    def record_validation(self, rule_name: str, outcome: str) -> None:
        key = outcome.upper() if outcome else "UNKNOWN"
        bucket = key if key in ("PASS", "FAIL", "ERROR", "SKIPPED", "AWAITING") else "ERROR"
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._data["validations_total"] += 1
            self._data["by_outcome"][bucket] = self._data["by_outcome"].get(bucket, 0) + 1
            if rule_name:
                rule_key = rule_name[:200]
                prior = self._data["rules_seen"].get(rule_key, {})
                self._data["rules_seen"][rule_key] = {
                    "last_outcome": bucket,
                    "last_run": now,
                    "runs": prior.get("runs", 0) + 1,
                }
            self._data["last_run"] = now
            if not self._data["first_run"]:
                self._data["first_run"] = now
            self._save()

    def record_composite_static(self) -> None:
        with self._lock:
            self._data["composite_static_runs"] += 1
            self._save()

    def record_negative_test(self) -> None:
        with self._lock:
            self._data["negative_tests_total"] += 1
            self._save()

    def record_fixture(self, op: str) -> None:
        key = {"save": "fixture_saves_total", "load": "fixture_loads_total"}.get(op)
        if not key:
            return
        with self._lock:
            self._data[key] += 1
            self._save()

    def snapshot(self) -> dict:
        with self._lock:
            rules = self._data.get("rules_seen", {})
            recent = sorted(
                ({"rule_name": k, **v} for k, v in rules.items()),
                key=lambda r: r.get("last_run") or "",
                reverse=True,
            )[:20]
            return {
                "validations_total": self._data["validations_total"],
                "by_outcome": dict(self._data["by_outcome"]),
                "composite_static_runs": self._data["composite_static_runs"],
                "negative_tests_total": self._data["negative_tests_total"],
                "fixture_saves_total": self._data["fixture_saves_total"],
                "fixture_loads_total": self._data["fixture_loads_total"],
                "rules_tracked": len(rules),
                "recent_rules": recent,
                "first_run": self._data["first_run"],
                "last_run": self._data["last_run"],
            }


metrics = MetricsCollector()


def _outcome_bucket(result: dict) -> str:
    """Collapse a validation result JSON into a single outcome bucket."""
    status = (result or {}).get("status", "")
    if not status:
        return "ERROR"
    status = str(status).upper()
    if status in ("PASS", "SUCCESS", "FIRED"):
        return "PASS"
    if status in ("FAIL", "FAILED", "NOT_FIRED"):
        return "FAIL"
    if status in ("INGESTED_AWAITING_VERIFICATION", "INGESTED_AWAITING_CASCADE_VERIFY"):
        return "AWAITING"
    if status.startswith("SKIPPED") or status == "USE_CASCADE_VALIDATE" or status == "NOT_COMPOSITE":
        return "SKIPPED"
    if status in ("STATIC_OK",):
        return "PASS"
    if status.startswith("STATIC_FAIL"):
        return "FAIL"
    return "ERROR"


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


DETERMINISTIC_MODE = os.getenv("DETERMINISTIC", "").lower() in ("1", "true", "yes")
_GEMINI_CACHE: dict = {}
_GEMINI_CACHE_LOCK = threading.Lock()


def _gemini(prompt: str, system: str = "", max_tokens: int = 8192, deterministic: bool | None = None) -> str:
    """Call Gemini and return text.

    When DETERMINISTIC mode is active (env DETERMINISTIC=1 or the deterministic
    flag is True), temperature is pinned to 0 and identical (prompt, system,
    model, max_tokens) tuples return a cached response. This makes CI runs
    reproducible at the cost of diversity across retries.
    """
    if deterministic is None:
        deterministic = DETERMINISTIC_MODE
    temperature = 0.0 if deterministic else 0.1

    cache_key = ""
    if deterministic:
        cache_key = hashlib.sha256(
            f"{GEMINI_MODEL}\0{system}\0{prompt}\0{max_tokens}".encode("utf-8")
        ).hexdigest()
        with _GEMINI_CACHE_LOCK:
            cached = _GEMINI_CACHE.get(cache_key)
        if cached is not None:
            return cached

    token = _get_adc_token()
    url = (f"https://us-central1-aiplatform.googleapis.com/v1/projects/{SECOPS_PROJECT_ID}"
           f"/locations/us-central1/publishers/google/models/{GEMINI_MODEL}:generateContent")
    body: dict = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature},
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
        logger.warning("Gemini response hit MAX_TOKENS limit; output may be truncated")
    parts = candidate.get("content", {}).get("parts", [])
    out = "".join(p.get("text", "") for p in parts)

    if deterministic and cache_key:
        with _GEMINI_CACHE_LOCK:
            _GEMINI_CACHE[cache_key] = out
    return out

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


VALID_UDM_TOP_LEVEL = {
    "metadata", "principal", "target", "src", "observer", "about", "intermediary",
    "security_result", "network", "authentication", "additional", "extracted",
    "extensions",
}

VALID_EVENT_TYPES = {
    "EVENTTYPE_UNSPECIFIED", "GENERIC_EVENT", "PROCESS_LAUNCH", "PROCESS_TERMINATION",
    "PROCESS_OPEN", "PROCESS_INJECTION", "PROCESS_MODULE_LOAD",
    "PROCESS_PRIVILEGE_ESCALATION", "PROCESS_UNCATEGORIZED",
    "FILE_CREATION", "FILE_DELETION", "FILE_MODIFICATION", "FILE_READ", "FILE_COPY",
    "FILE_OPEN", "FILE_MOVE", "FILE_SYNC", "FILE_UNCATEGORIZED",
    "NETWORK_CONNECTION", "NETWORK_HTTP", "NETWORK_DNS", "NETWORK_DHCP",
    "NETWORK_FLOW", "NETWORK_FTP", "NETWORK_SMTP", "NETWORK_UNCATEGORIZED",
    "USER_LOGIN", "USER_LOGOUT", "USER_CREATION", "USER_DELETION",
    "USER_CHANGE_PASSWORD", "USER_CHANGE_PERMISSIONS", "USER_COMMUNICATION",
    "USER_BADGE_IN", "USER_RESOURCE_ACCESS", "USER_RESOURCE_CREATION",
    "USER_RESOURCE_DELETION", "USER_RESOURCE_UPDATE_CONTENT",
    "USER_RESOURCE_UPDATE_PERMISSIONS", "USER_UNCATEGORIZED",
    "EMAIL_TRANSACTION", "EMAIL_UNCATEGORIZED",
    "SCAN_FILE", "SCAN_HOST", "SCAN_VULN_HOST", "SCAN_VULN_NETWORK",
    "SCAN_NETWORK", "SCAN_PROCESS", "SCAN_UNCATEGORIZED",
    "SCHEDULED_TASK_CREATION", "SCHEDULED_TASK_DELETION",
    "SCHEDULED_TASK_DISABLE", "SCHEDULED_TASK_ENABLE",
    "SCHEDULED_TASK_MODIFICATION", "SCHEDULED_TASK_UNCATEGORIZED",
    "SYSTEM_AUDIT_LOG_UNCATEGORIZED", "SYSTEM_AUDIT_LOG_WIPE",
    "SERVICE_CREATION", "SERVICE_DELETION", "SERVICE_START", "SERVICE_STOP",
    "SERVICE_MODIFICATION", "SERVICE_UNSPECIFIED",
    "REGISTRY_CREATION", "REGISTRY_MODIFICATION", "REGISTRY_DELETION",
    "REGISTRY_UNCATEGORIZED",
    "SETTING_CREATION", "SETTING_MODIFICATION", "SETTING_DELETION",
    "SETTING_UNCATEGORIZED",
    "MUTEX_CREATION", "MUTEX_UNCATEGORIZED",
    "RESOURCE_CREATION", "RESOURCE_DELETION", "RESOURCE_PERMISSIONS_CHANGE",
    "RESOURCE_READ", "RESOURCE_WRITTEN",
    "GROUP_CREATION", "GROUP_DELETION", "GROUP_MODIFICATION", "GROUP_UNCATEGORIZED",
    "STATUS_HEARTBEAT", "STATUS_STARTUP", "STATUS_SHUTDOWN", "STATUS_UPDATE",
    "ANALYST_UPDATE_VERDICT", "ANALYST_UPDATE_REPUTATION",
    "ANALYST_UPDATE_SEVERITY_SCORE", "ANALYST_UPDATE_STATUS",
    "ANALYST_UPDATE_PRIORITY", "ANALYST_UPDATE_REASON",
    "ANALYST_UPDATE_ROOT_CAUSE", "ANALYST_UPDATE_COMMENT",
}

EVENT_TYPE_ALIASES = {
    "PROCESS_ACTIVITY": "PROCESS_LAUNCH",
    "PROCESS_CREATE": "PROCESS_LAUNCH",
    "PROCESS_CREATION": "PROCESS_LAUNCH",
    "PROCESS_START": "PROCESS_LAUNCH",
    "PROCESS_END": "PROCESS_TERMINATION",
    "PROCESS_EXIT": "PROCESS_TERMINATION",
    "PROCESS_KILL": "PROCESS_TERMINATION",
    "FILE_ACTIVITY": "FILE_MODIFICATION",
    "FILE_WRITE": "FILE_MODIFICATION",
    "FILE_ACCESS": "FILE_READ",
    "NETWORK_ACTIVITY": "NETWORK_CONNECTION",
    "NETWORK_TRAFFIC": "NETWORK_CONNECTION",
    "DNS_QUERY": "NETWORK_DNS",
    "HTTP_REQUEST": "NETWORK_HTTP",
    "LOGIN": "USER_LOGIN",
    "LOGON": "USER_LOGIN",
    "LOGOUT": "USER_LOGOUT",
    "LOGOFF": "USER_LOGOUT",
    "AUTHENTICATION": "USER_LOGIN",
    "REGISTRY_ACTIVITY": "REGISTRY_MODIFICATION",
    "REGISTRY_WRITE": "REGISTRY_MODIFICATION",
    "REGISTRY_CHANGE": "REGISTRY_MODIFICATION",
    "SCHEDULED_TASK": "SCHEDULED_TASK_CREATION",
    "SERVICE_ACTIVITY": "SERVICE_MODIFICATION",
    "EMAIL": "EMAIL_TRANSACTION",
}


def _normalize_event_type(et: str, event: dict) -> str:
    """Map invalid event_type strings to a valid UDM enum.
    Priority: alias table → field-based inference → GENERIC_EVENT."""
    if not et:
        et = ""
    et_upper = str(et).upper().strip()
    if et_upper in VALID_EVENT_TYPES:
        return et_upper
    if et_upper in EVENT_TYPE_ALIASES:
        return EVENT_TYPE_ALIASES[et_upper]
    # Field-based inference as fallback
    has_process = any(
        isinstance(event.get(n), dict) and isinstance(event[n].get("process"), dict)
        for n in ("principal", "target", "src")
    )
    has_network = isinstance(event.get("network"), dict)
    has_file = any(
        isinstance(event.get(n), dict) and isinstance(event[n].get("file"), dict)
        for n in ("principal", "target", "src")
    )
    has_auth_ctx = isinstance(event.get("authentication"), dict) or (
        isinstance(event.get("security_result"), list)
    )
    if has_process:
        return "PROCESS_LAUNCH"
    if has_network:
        return "NETWORK_CONNECTION"
    if has_file:
        return "FILE_MODIFICATION"
    if has_auth_ctx:
        return "USER_LOGIN"
    return "GENERIC_EVENT"


def _sanitize_udm_event(e: dict) -> dict:
    """Strip fields that fail UDM schema validation and fix type mismatches."""
    # Remap common Gemini mistakes BEFORE stripping unknown keys:
    # 'extracted_fields' (flat) should be 'extracted.fields' (nested) per UDM schema
    if "extracted_fields" in e and "extracted" not in e:
        ef = e.pop("extracted_fields")
        if isinstance(ef, dict):
            e["extracted"] = {"fields": {str(k): str(v) for k, v in ef.items()}}

    # Strip any top-level keys that are not real UDM fields
    for k in list(e.keys()):
        if k not in VALID_UDM_TOP_LEVEL:
            e.pop(k)

    # metadata — strip fields that cause ingestion failures
    meta = e.get("metadata", {})
    meta.pop("ingestion_labels", None)
    # metadata.id must be a valid plain UUID — strip it, SDK will generate a correct one
    meta.pop("id", None)
    # Normalize event_type — map aliases and invalid values to valid enums
    if "event_type" in meta:
        meta["event_type"] = _normalize_event_type(meta.get("event_type"), e)
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


# ═══════════════════════════════════════════════════════════════
# PARSER-PATH VALIDATION (raw logs through Chronicle parser)
# ═══════════════════════════════════════════════════════════════

# Log types the generator knows how to produce without extra fixtures.
# Expand as needed; Chronicle supports hundreds more via ingest_log.
KNOWN_PARSER_LOG_TYPES = {
    "WINEVTLOG": "Windows Event Log (XML). Use EventID 4624/4625 for logon, 4688 for process creation, 4663 for object access.",
    "WINDOWS_SYSMON": "Sysmon event log (XML). EventID 1 process create, 3 network connect, 7 image load, 11 file create.",
    "OKTA": "Okta system log (JSON). eventType like 'user.session.start', outcome.result.",
    "GCP_CLOUDAUDIT": "GCP Cloud Audit Log (JSON with protoPayload, authenticationInfo, methodName).",
    "AZURE_AD": "Azure AD sign-in / audit log (JSON with userPrincipalName, ipAddress, status.errorCode).",
    "CROWDSTRIKE_FALCON": "CrowdStrike Falcon detection JSON (ExternalApiType, DetectDescription, ComputerName).",
    "CISCO_ASA": "Cisco ASA syslog (%ASA-X-NNNNNN: ...).",
    "LINUX_SYSLOG": "Generic RFC5424 syslog.",
    "O365": "Microsoft 365 unified audit log (JSON with Operation, UserId, ClientIP).",
    "AWS_CLOUDTRAIL": "AWS CloudTrail (JSON with eventName, userIdentity, sourceIPAddress).",
}


@app_mcp.tool()
def generate_native_log_events(analysis_json: str, log_type: str, count: int = 5) -> str:
    """Generate raw logs in a native format (not UDM) so Chronicle's parser
    runs the full ingest path. Use this when you need to prove a rule fires
    end-to-end including parser behavior, not just on a synthetic UDM payload.

    log_type: Chronicle ingestion log type (e.g. WINEVTLOG, OKTA,
    GCP_CLOUDAUDIT). See KNOWN_PARSER_LOG_TYPES for supported shapes.
    Any Chronicle-supported log_type works; the generator asks Gemini for the
    right native format for that source.

    Returns {log_type, logs: [raw_log_strings], count}.
    """
    try:
        analysis = json.loads(analysis_json) if isinstance(analysis_json, str) else analysis_json
    except Exception:
        analysis = {"trigger_summary": analysis_json}

    min_needed = analysis.get("min_event_count", count)
    actual_count = max(count, min_needed)
    hint = KNOWN_PARSER_LOG_TYPES.get(log_type.upper(), f"Chronicle log type {log_type}. Produce a valid native log for this source.")
    now = datetime.now(timezone.utc)
    timestamps = [(now + timedelta(minutes=i)).strftime('%Y-%m-%dT%H:%M:%S.000Z') for i in range(actual_count)]

    prompt = f"""Generate {actual_count} RAW LOG ENTRIES in the NATIVE format for Chronicle log_type {log_type}.

{hint}

These logs MUST satisfy the YARA-L rule analysis below when Chronicle's built-in
parser converts them to UDM. Do NOT produce UDM. Produce the native source format
(XML for Windows Event Log, JSON for cloud audit logs, syslog strings for network
devices, etc.).

Use THESE exact timestamps for the events (spread across a 10-minute window):
{json.dumps(timestamps)}

Rule analysis:
{json.dumps(analysis, indent=2)}

Event breakdown needed: {json.dumps(analysis.get("event_breakdown", {})) or "see condition block"}

Return ONLY this JSON shape, no markdown, no commentary:
{{
  "logs": [
    "<raw log string 1>",
    "<raw log string 2>",
    ...{actual_count - 1} more...
  ]
}}

For multi-line native formats (Windows Event Log XML), keep each log as one
JSON string with \\n line breaks preserved. For JSON-native formats (Okta,
GCP audit, CloudTrail), each log is a stringified JSON object."""

    try:
        result = _gemini(prompt, max_tokens=8192)
        parsed = _extract_json(result)
        if not isinstance(parsed, dict) or "logs" not in parsed:
            return json.dumps({"error": f"Generator returned unexpected format: {str(result)[:300]}"})
        logs = parsed["logs"] if isinstance(parsed["logs"], list) else [parsed["logs"]]
        return json.dumps({
            "log_type": log_type.upper(),
            "logs": logs,
            "count": len(logs),
            "note": "Raw native logs. Ingest via ingest_native_logs; parser runs; rule evaluates against parsed UDM.",
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def ingest_native_logs(logs_json: str, log_type: str) -> str:
    """Ingest raw native-format logs through Chronicle's parser path.
    Expects the output of generate_native_log_events ({log_type, logs: [...]}).

    Parser latency is typically 30 seconds to 5 minutes depending on the log
    source. Use verify_rule_triggered with a longer minutes_back window.
    """
    try:
        data = json.loads(logs_json) if isinstance(logs_json, str) else logs_json
        logs = data.get("logs") if isinstance(data, dict) else data
        if not logs:
            return json.dumps({"error": "No logs to ingest"})
        if not isinstance(logs, list):
            logs = [logs]

        from secops import SecOpsClient
        client = SecOpsClient().chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION,
        )
        validation_id = f"yaral-test-{uuid.uuid4().hex[:12]}"
        ingestion_time = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        result = client.ingest_log(log_type=log_type.upper(), logs=logs)
        return json.dumps({
            "status": "ingested",
            "validation_id": validation_id,
            "method": "ingest_log",
            "log_type": log_type.upper(),
            "event_count": len(logs),
            "ingestion_time": ingestion_time,
            "api_response": result,
            "message": f"Ingested {len(logs)} raw {log_type.upper()} logs. Chronicle parser will convert to UDM. Expect 30s-5min before detection.",
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


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
            logger.info(f"Ingesting {len(sanitized)} UDM events via ingest_log(log_type=UDM) — first: {str(sanitized[0])[:300]}")

            responses = []
            for e in sanitized:
                r = client.ingest_log(log_type="UDM", log_message=json.dumps(e))
                responses.append(r)
            return json.dumps({
                "status": "ingested",
                "validation_id": validation_id,
                "method": "ingest_log(UDM)",
                "event_count": len(sanitized),
                "ingestion_time": ingestion_time,
                "api_response": responses,
                "message": f"Ingested {len(sanitized)} UDM events via ingest_log(log_type=UDM). Parser skipped; rule evaluates within 30-60s for LIVE rules.",
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


def _fetch_rule_texts_by_name(names: list) -> dict:
    """Look up deployed rule source text for each name. Returns {found: {name: text}, missing: [names]}.
    Used by cascade_validate to feed real base rule bodies into the generator."""
    from secops import SecOpsClient
    client = SecOpsClient().chronicle(
        customer_id=SECOPS_CUSTOMER_ID,
        project_id=SECOPS_PROJECT_ID,
        region=SECOPS_REGION,
    )
    rules = client.list_rules(view="FULL", as_list=True)
    by_display: dict = {}
    by_decl: dict = {}
    for r in rules:
        text = r.get("text", "") or ""
        display = (r.get("displayName", "") or "").lower()
        if display:
            by_display[display] = text
        m = re.search(r'^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{', text, re.MULTILINE)
        if m:
            by_decl[m.group(1).lower()] = text

    found: dict = {}
    missing: list = []
    for name in names:
        key = (name or "").strip().lower()
        if not key:
            continue
        text = by_decl.get(key) or by_display.get(key)
        if text:
            found[name] = text
        else:
            missing.append(name)
    return {"found": found, "missing": missing}


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


_USER_KEYS = ("user", "username", "userid", "principal_user", "principal_user_userid",
              "user_userid", "principal_username", "target_user", "target_user_userid")
_HOST_KEYS = ("hostname", "host", "principal_hostname", "target_hostname",
              "src_hostname", "principal_host")
_IP_KEYS   = ("src_ip", "source_ip", "ip", "principal_ip", "target_ip", "src_address")
_PROC_KEYS = ("principal_process_command_line", "target_process_command_line",
              "command_line", "principal_process_file_full_path",
              "target_process_file_full_path", "process_file_full_path", "file_full_path")


def _first_scalar(fields: dict, keys: tuple) -> str:
    for k in keys:
        v = fields.get(k)
        if v is None:
            continue
        if isinstance(v, list):
            v = next((str(x) for x in v if x), "")
        v = str(v).strip()
        if v and v.lower() != "unknown":
            return v
    return ""


def _scan_events_for(collection_elements: list, path: list[str]) -> str:
    """Walk a UDM path in the first event that has it; return first non-empty scalar."""
    for elem in collection_elements:
        for ref in elem.get("references", []):
            node = ref.get("event", {})
            for p in path:
                if isinstance(node, dict):
                    node = node.get(p)
                else:
                    node = None
                    break
            if isinstance(node, list) and node:
                node = node[0]
            if isinstance(node, str) and node:
                return node
    return ""


def _summarize_detections(detections: list) -> list:
    """Turn raw detection JSON into plain-English summaries the user can read."""
    summaries = []
    for det in detections:
        rule_det = (det.get("detection") or [{}])[0]
        # detectionFields can be repeated (array of {key,value}) OR nested under outcomes
        raw_fields = rule_det.get("detectionFields", []) or []
        fields = {}
        for f in raw_fields:
            k = f.get("key")
            v = f.get("value") or f.get("values")
            if k:
                fields[k] = v
        # Also pull from outcomes if present
        for o in rule_det.get("outcomes", []) or []:
            k = o.get("variable") or o.get("key")
            v = o.get("value") or o.get("values")
            if k and k not in fields:
                fields[k] = v

        severity = rule_det.get("severity", "")
        rule_n   = rule_det.get("ruleName", "")

        collection = det.get("collectionElements", []) or []
        user = _first_scalar(fields, _USER_KEYS) or _scan_events_for(collection, ["principal", "user", "userid"]) or _scan_events_for(collection, ["target", "user", "userid"])
        host = _first_scalar(fields, _HOST_KEYS) or _scan_events_for(collection, ["principal", "hostname"]) or _scan_events_for(collection, ["target", "hostname"])
        src  = _first_scalar(fields, _IP_KEYS)  or _scan_events_for(collection, ["principal", "ip"])  or _scan_events_for(collection, ["src", "ip"])
        proc = _first_scalar(fields, _PROC_KEYS) or _scan_events_for(collection, ["target", "process", "file", "full_path"]) or _scan_events_for(collection, ["principal", "process", "command_line"])

        # Group collectionElements by label
        groups = {}
        for elem in collection:
            label = elem.get("label", "events")
            times = []
            for ref in elem.get("references", []):
                ts = ref.get("event", {}).get("metadata", {}).get("eventTimestamp", "")
                if ts:
                    times.append(ts)
            if times:
                groups[label] = sorted(times)

        fail_times    = groups.get("fail") or groups.get("failed") or groups.get("failure")
        success_times = groups.get("success") or groups.get("successful") or groups.get("allowed")

        def _entity():
            bits = []
            if user: bits.append(f"user `{user}`")
            if host: bits.append(f"on host `{host}`")
            if src:  bits.append(f"from IP `{src}`")
            return " ".join(bits) if bits else "an unidentified entity"

        if fail_times and success_times:
            line = (
                f"{_entity()} failed {len(fail_times)} login attempts between "
                f"{fail_times[0][11:19]} and {fail_times[-1][11:19]} UTC, then successfully "
                f"logged in at {success_times[0][11:19]} UTC."
            )
        else:
            total_events = sum(len(t) for t in groups.values())
            first = min((t[0] for t in groups.values() if t), default="")
            last  = max((t[-1] for t in groups.values() if t), default="")
            proc_blurb = f" running `{proc}`" if proc else ""
            if total_events and first and last:
                line = (
                    f"{_entity()}{proc_blurb} triggered {total_events} correlated events "
                    f"between {first[11:19]} and {last[11:19]} UTC."
                )
            elif total_events:
                line = f"{_entity()}{proc_blurb} triggered {total_events} events."
            else:
                line = f"{_entity()}{proc_blurb} triggered rule {rule_n}."

        headline = f"🚨 [{severity}] Detection fired on rule `{rule_n}`" if severity else f"🚨 Detection fired on rule `{rule_n}`"
        summaries.append(f"{headline}\n{line}")
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
def run_full_validation(
    rule_text: str,
    rule_name: str = "",
    wait_seconds: int = 120,
    validation_mode: str = "udm_direct",
    log_type: str = "",
) -> str:
    """End-to-end YARA-L rule validation.

    validation_mode:
      udm_direct  (default) Generate synthetic UDM events, ingest directly
                  via events:import, skip the parser. Fast (~60-120s). Proves
                  the rule's UDM conditions match a well-formed payload.
                  Does NOT exercise Chronicle's parser.
      parser_path Generate raw native logs (Windows Event XML, Okta JSON,
                  GCP Cloud Audit JSON, etc.) and ingest via ingest_log so
                  Chronicle's parser runs. Slow (parser latency ~30s-5min
                  plus rule eval). Proves the full ingest path. Requires
                  log_type (e.g. WINEVTLOG, OKTA, GCP_CLOUDAUDIT).
      both        Run udm_direct first, then parser_path. Returns both
                  verdicts so the caller can gate on either or both.

    log_type: required when validation_mode is parser_path or both.
    """
    results: dict = {"validation_mode": validation_mode}
    try:
        comp = _detect_composite(rule_text)
        if comp["is_composite"]:
            return json.dumps({
                "status": "USE_CASCADE_VALIDATE",
                "is_composite": True,
                "heuristic": comp,
                "message": _COMPOSITE_WARNING,
                "next_step": "Use cascade_validate (or the 'Composite Validate' button) or composite_static_validate for CI.",
            })

        mode = (validation_mode or "udm_direct").lower()
        if mode not in ("udm_direct", "parser_path", "both"):
            return json.dumps({"status": "ERROR", "error": f"Unknown validation_mode '{validation_mode}'. Use udm_direct, parser_path, or both."})
        if mode in ("parser_path", "both") and not log_type:
            return json.dumps({"status": "ERROR", "error": "log_type is required when validation_mode is parser_path or both (e.g. WINEVTLOG, OKTA, GCP_CLOUDAUDIT)."})

        logger.info("Step 1: Analyzing YARA-L rule...")
        analysis_raw = analyze_yara_l_rule(rule_text)
        analysis = json.loads(analysis_raw)
        results["analysis"] = analysis
        detected_name = analysis.get("rule_name", rule_name or "unknown_rule")
        if not rule_name:
            rule_name = detected_name
        min_count = analysis.get("min_event_count", 5)

        udm_ingest: dict = {}
        parser_ingest: dict = {}

        if mode in ("udm_direct", "both"):
            logger.info("Generating synthetic UDM events...")
            events_raw = generate_synthetic_events(analysis_raw, count=max(5, min_count))
            events_data = json.loads(events_raw)
            results["udm_generation"] = events_data
            if "error" in events_data:
                return json.dumps({"status": "FAILED", "stage": "udm_generation", "results": results})
            logger.info("Ingesting UDM events (bypassing parser)...")
            ingest_raw = ingest_synthetic_events(events_raw)
            udm_ingest = json.loads(ingest_raw)
            results["udm_ingestion"] = udm_ingest
            if udm_ingest.get("status") not in ("ingested", "ingested_fallback"):
                return json.dumps({"status": "FAILED", "stage": "udm_ingestion", "results": results})

        if mode in ("parser_path", "both"):
            logger.info(f"Generating native {log_type} logs for parser path...")
            native_raw = generate_native_log_events(analysis_raw, log_type=log_type, count=max(5, min_count))
            native_data = json.loads(native_raw)
            results["parser_generation"] = native_data
            if "error" in native_data:
                return json.dumps({"status": "FAILED", "stage": "parser_generation", "results": results})
            logger.info(f"Ingesting {log_type} logs through the parser...")
            ingest_raw = ingest_native_logs(native_raw, log_type=log_type)
            parser_ingest = json.loads(ingest_raw)
            results["parser_ingestion"] = parser_ingest
            if parser_ingest.get("status") != "ingested":
                return json.dumps({"status": "FAILED", "stage": "parser_ingestion", "results": results})

        verify_targets = []
        if udm_ingest:
            verify_targets.append({
                "label": "udm_direct",
                "validation_id": udm_ingest.get("validation_id", ""),
                "recommended_wait_s": wait_seconds,
            })
        if parser_ingest:
            parser_wait = max(wait_seconds, 300)
            verify_targets.append({
                "label": "parser_path",
                "validation_id": parser_ingest.get("validation_id", ""),
                "recommended_wait_s": parser_wait,
            })

        return json.dumps({
            "status": "INGESTED_AWAITING_VERIFICATION",
            "rule_name": rule_name,
            "validation_mode": mode,
            "log_type": log_type.upper() if log_type else "",
            "verify_targets": verify_targets,
            "event_count": (udm_ingest.get("event_count") or 0) + (parser_ingest.get("event_count") or 0),
            "validation_id": verify_targets[0]["validation_id"] if verify_targets else "",
            "next_step": (
                "Call verify_rule_triggered with each validation_id. "
                "udm_direct is typically ready in 60-120s; parser_path needs 5+ minutes for parser + rule eval."
            ),
            "results": results,
            "ingestion_time": (udm_ingest.get("ingestion_time") or parser_ingest.get("ingestion_time") or ""),
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
        responses = [client.ingest_log(log_type="UDM", log_message=json.dumps(e)) for e in sanitized]
        return json.dumps({
            "status": "ingested",
            "validation_id": validation_id,
            "event_count": len(sanitized),
            "ingestion_time": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            "api_response": responses,
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
# Backend: GCS if FIXTURE_BUCKET env var is set; else local disk.
# ═══════════════════════════════════════════════════════════════

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
FIXTURE_BUCKET = os.getenv("FIXTURE_BUCKET", "")
FIXTURE_PREFIX = os.getenv("FIXTURE_PREFIX", "fixtures/")
RULE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_rules")
RULE_PREFIX = os.getenv("RULE_PREFIX", "saved_rules/")


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


def _gcs_bucket():
    from google.cloud import storage
    client = storage.Client(project=SECOPS_PROJECT_ID) if SECOPS_PROJECT_ID else storage.Client()
    return client.bucket(FIXTURE_BUCKET)


def _fixture_backend() -> str:
    return "gcs" if FIXTURE_BUCKET else "local"


def _gcs_blob_name(name: str) -> str:
    return f"{FIXTURE_PREFIX}{name}.json"


def _fixture_write(name: str, payload: dict) -> str:
    """Returns a location string describing where the fixture was written."""
    body = json.dumps(payload, indent=2)
    if FIXTURE_BUCKET:
        bucket = _gcs_bucket()
        blob = bucket.blob(_gcs_blob_name(name))
        blob.upload_from_string(body, content_type="application/json")
        return f"gs://{FIXTURE_BUCKET}/{_gcs_blob_name(name)}"
    os.makedirs(FIXTURE_DIR, exist_ok=True)
    path = os.path.join(FIXTURE_DIR, f"{name}.json")
    with open(path, "w") as f:
        f.write(body)
    return path


def _fixture_read(name: str) -> dict | None:
    if FIXTURE_BUCKET:
        bucket = _gcs_bucket()
        blob = bucket.blob(_gcs_blob_name(name))
        if not blob.exists():
            return None
        return json.loads(blob.download_as_text())
    path = os.path.join(FIXTURE_DIR, f"{name}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def _fixture_list() -> list[dict]:
    items = []
    if FIXTURE_BUCKET:
        bucket = _gcs_bucket()
        for blob in bucket.list_blobs(prefix=FIXTURE_PREFIX):
            if not blob.name.endswith(".json"):
                continue
            try:
                d = json.loads(blob.download_as_text())
                items.append({
                    "file": blob.name.rsplit("/", 1)[-1],
                    "rule_name": d.get("rule_name", ""),
                    "saved_at": d.get("saved_at", ""),
                    "event_count": d.get("event_count", len(d.get("events", []))),
                })
            except Exception:
                continue
        return items
    if not os.path.isdir(FIXTURE_DIR):
        return []
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
    return items


@app_mcp.tool()
def save_fixture(rule_name: str, events_json: str, metadata_json: str = "") -> str:
    """Save the events that successfully validated a rule as a reusable fixture.
    Stored in GCS if FIXTURE_BUCKET is set, else local disk."""
    try:
        events_data = json.loads(events_json) if isinstance(events_json, str) else events_json
        events = events_data.get("events", events_data) if isinstance(events_data, dict) else events_data
        meta = json.loads(metadata_json) if metadata_json else {}

        name = _sanitize_fixture_name(rule_name)
        fixture = {
            "rule_name": rule_name,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "event_count": len(events),
            "events": events,
            "metadata": meta,
        }
        location = _fixture_write(name, fixture)
        return json.dumps({"status": "saved", "location": location, "backend": _fixture_backend(), "rule_name": rule_name, "event_count": len(events)})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def load_fixture(rule_name: str, refresh_timestamps: bool = True) -> str:
    """Load a saved fixture for replay. If refresh_timestamps=True, rewrites timestamps to now."""
    try:
        name = _sanitize_fixture_name(rule_name)
        fixture = _fixture_read(name)
        if fixture is None:
            return json.dumps({"error": f"No fixture for '{rule_name}' (backend: {_fixture_backend()})"})
        events = fixture.get("events", [])
        if refresh_timestamps:
            events = _reset_timestamps(events)
        return json.dumps({
            "status": "loaded",
            "backend": _fixture_backend(),
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
        items = _fixture_list()
        return json.dumps({"fixtures": items, "count": len(items), "backend": _fixture_backend()})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# RULE LIBRARY — save and recall YARA-L rules
# Same backend as fixtures; separate namespace so "Clear & Start Over"
# doesn't wipe previous work.
# ═══════════════════════════════════════════════════════════════


def _rule_blob_name(name: str) -> str:
    return f"{RULE_PREFIX}{name}.json"


def _rule_write(name: str, payload: dict) -> str:
    body = json.dumps(payload, indent=2)
    if FIXTURE_BUCKET:
        bucket = _gcs_bucket()
        blob = bucket.blob(_rule_blob_name(name))
        blob.upload_from_string(body, content_type="application/json")
        return f"gs://{FIXTURE_BUCKET}/{_rule_blob_name(name)}"
    os.makedirs(RULE_DIR, exist_ok=True)
    path = os.path.join(RULE_DIR, f"{name}.json")
    with open(path, "w") as f:
        f.write(body)
    return path


def _rule_read(name: str) -> dict | None:
    if FIXTURE_BUCKET:
        bucket = _gcs_bucket()
        blob = bucket.blob(_rule_blob_name(name))
        if not blob.exists():
            return None
        return json.loads(blob.download_as_text())
    path = os.path.join(RULE_DIR, f"{name}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def _rule_list() -> list[dict]:
    items = []
    if FIXTURE_BUCKET:
        bucket = _gcs_bucket()
        for blob in bucket.list_blobs(prefix=RULE_PREFIX):
            if not blob.name.endswith(".json"):
                continue
            try:
                d = json.loads(blob.download_as_text())
                items.append({
                    "file": blob.name.rsplit("/", 1)[-1],
                    "rule_name": d.get("rule_name", ""),
                    "saved_at": d.get("saved_at", ""),
                    "source": d.get("source", "unknown"),
                    "notes": d.get("notes", ""),
                })
            except Exception:
                continue
        return sorted(items, key=lambda r: r.get("saved_at", ""), reverse=True)
    if not os.path.isdir(RULE_DIR):
        return []
    for fn in sorted(os.listdir(RULE_DIR)):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(RULE_DIR, fn)) as f:
                d = json.load(f)
            items.append({
                "file": fn,
                "rule_name": d.get("rule_name", fn[:-5]),
                "saved_at": d.get("saved_at", ""),
                "source": d.get("source", "unknown"),
                "notes": d.get("notes", ""),
            })
        except Exception:
            continue
    return sorted(items, key=lambda r: r.get("saved_at", ""), reverse=True)


def _rule_delete(name: str) -> bool:
    if FIXTURE_BUCKET:
        bucket = _gcs_bucket()
        blob = bucket.blob(_rule_blob_name(name))
        if not blob.exists():
            return False
        blob.delete()
        return True
    path = os.path.join(RULE_DIR, f"{name}.json")
    if not os.path.exists(path):
        return False
    os.remove(path)
    return True


@app_mcp.tool()
def save_rule(rule_name: str, rule_text: str, notes: str = "", source: str = "user") -> str:
    """Persist a YARA-L rule so it can be recalled after 'Clear & Start Over'.
    Stored in the same backend as fixtures (GCS if FIXTURE_BUCKET is set,
    otherwise local disk) under a separate saved_rules/ namespace."""
    try:
        if not rule_name or not rule_text:
            return json.dumps({"error": "rule_name and rule_text required"})
        name = _sanitize_fixture_name(rule_name)
        payload = {
            "rule_name": rule_name,
            "rule_text": rule_text,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "notes": notes,
        }
        location = _rule_write(name, payload)
        return json.dumps({"status": "saved", "rule_name": rule_name, "location": location})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def load_rule(rule_name: str) -> str:
    """Load a previously saved YARA-L rule by name."""
    try:
        name = _sanitize_fixture_name(rule_name)
        rec = _rule_read(name)
        if rec is None:
            return json.dumps({"error": f"rule '{rule_name}' not found"})
        return json.dumps(rec)
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def list_saved_rules() -> str:
    """List saved YARA-L rules with metadata (name, saved_at, source, notes)."""
    try:
        items = _rule_list()
        return json.dumps({"rules": items, "count": len(items), "backend": _fixture_backend()})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def delete_saved_rule(rule_name: str) -> str:
    """Remove a rule from the saved library."""
    try:
        name = _sanitize_fixture_name(rule_name)
        ok = _rule_delete(name)
        return json.dumps({"status": "deleted" if ok else "not_found", "rule_name": rule_name})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# RULE GENERATION — produce a YARA-L rule from plain English
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def generate_yara_l_rule(description: str, event_type_hint: str = "", severity: str = "MEDIUM") -> str:
    """Generate a YARA-L 2.0 rule from a plain-English description.

    description: what the rule should detect (e.g. "5 failed logins followed
      by a successful one from the same IP within 10 minutes").
    event_type_hint: optional UDM event_type to anchor generation
      (USER_LOGIN, NETWORK_CONNECTION, PROCESS_LAUNCH, NETWORK_DNS, etc.).
    severity: LOW / MEDIUM / HIGH / CRITICAL.

    Returns {rule_name, rule_text, rationale}. The rule is NOT saved or
    deployed automatically; pipe it through analyze_yara_l_rule first to
    confirm it parses, then run_full_validation to confirm it fires.
    """
    sev = (severity or "MEDIUM").upper()
    if sev not in ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        sev = "MEDIUM"
    hint = event_type_hint.strip().upper() if event_type_hint else ""
    hint_block = f"Target UDM event_type: {hint}." if hint else "Pick the correct UDM event_type from the description."

    prompt = f"""Write a single YARA-L 2.0 rule that detects the behaviour described below.

Description:
{description}

{hint_block}
Severity: {sev}

Hard requirements:
- Output must be ONE YARA-L 2.0 rule. No multiple rules, no explanation, no
  markdown fences in the rule body.
- Use valid UDM field paths ($e.metadata.event_type, $e.principal.user.userid,
  $e.principal.ip, $e.target.user.userid, $e.target.hostname,
  $e.security_result.action, $e.network.application_protocol, etc.).
- metadata.event_type must be a valid UDM enum string.
- Include meta{{}} with author="yaral-validator-ai", description="<short>",
  severity="{sev}", and mitre_attack_tactic / mitre_attack_technique when
  obvious from the description.
- If the rule needs counts (brute force, volume-based), use a match{{}} block
  with a time window and a condition with #e >= N.
- Do NOT reference external rules ($var.detection.*) — that makes it a
  composite and the user will validate single-rule first.
- Rule name must be a snake_case identifier, no spaces.

Return JSON only (no markdown fence):
{{
  "rule_name": "<snake_case name>",
  "rule_text": "<the rule, newlines preserved in the JSON string>",
  "rationale": "<one paragraph explaining what the rule fires on and the UDM fields it uses>"
}}"""

    try:
        result = _gemini(prompt, max_tokens=4096)
        parsed = _extract_json(result)
        if not isinstance(parsed, dict) or "rule_text" not in parsed:
            return json.dumps({"error": f"Generator returned unexpected format: {str(result)[:400]}"})
        parsed.setdefault("severity", sev)
        parsed.setdefault("description", description)
        return json.dumps(parsed, indent=2)
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
    """Heuristic: does this rule reference other rules' detections (true composite)?"""
    # Only rules that reference $var.detection.* or rule_name = "..." are true composites
    # that chain off other rules' detection output.
    has_detection_ref = bool(re.search(r"\$\w+\.detection\.", rule_text))
    has_rule_name_ref = bool(re.search(r"\.rule_name\s*=\s*\"", rule_text))
    is_composite      = has_detection_ref or has_rule_name_ref
    match_window      = ""
    m = re.search(r"match:\s*[^\n]*?over\s+(\d+[smhd])", rule_text)
    if m:
        match_window = m.group(1)
    return {
        "is_composite": is_composite,
        "has_detection_ref": has_detection_ref,
        "has_rule_name_ref": has_rule_name_ref,
        "match_window": match_window,
        "base_rule_refs": _extract_base_rule_refs(rule_text),
    }


def _extract_base_rule_refs(rule_text: str) -> list:
    """Pull every literal base-rule name referenced in a composite via
    $var.detection.detection.rule_name = "..." or similar selectors. De-duplicated, preserves order."""
    seen: list = []
    for m in re.finditer(r'\.rule_name\s*(?:=|in)\s*(?:\[\s*)?"([^"]+)"', rule_text):
        name = m.group(1).strip()
        if name and name not in seen:
            seen.append(name)
    # Also catch multi-value `rule_name in ["a", "b"]` lists
    for m in re.finditer(r'\.rule_name\s+in\s*\[([^\]]+)\]', rule_text):
        for lit in re.findall(r'"([^"]+)"', m.group(1)):
            lit = lit.strip()
            if lit and lit not in seen:
                seen.append(lit)
    return seen


# Chronicle composite-rule constraints that shape the wait time for validation:
# 1. Retrohunts on composite rules return an empty name silently — cannot fast-forward.
# 2. Match windows >1h are forced to HOURLY cadence (≤1h wait per evaluation cycle).
# 3. Match windows ≥24h are forced to DAILY cadence (≤24h wait per evaluation cycle).
# 4. Match windows <1h run LIVE but re-evaluation is still on an internal schedule that
#    may not chain instantly off newly-ingested base detections — expect up to an hour.
# The tool will still validate composites — it just needs the user to know the wait.
_COMPOSITE_WARNING = (
    "Composite rules correlate detections from other rules via $var.detection.*. "
    "Validating them is SUPPORTED but SLOW due to Chronicle's scheduling behavior: "
    "(a) retrohunts don't work on composite rules, (b) match windows >1h force HOURLY "
    "cadence, (c) match windows ≥24h force DAILY cadence, and (d) even LIVE composites "
    "evaluate on Chronicle's internal schedule — not instantly off new base detections. "
    "Expect the full cascade to take up to 1 hour for HOURLY rules and up to 24 hours "
    "for DAILY rules. The only reliable way to test a composite is to use a match "
    "window ≥1h (HOURLY cadence) and wait for the next run cycle."
)


def _estimate_composite_wait(time_window: str) -> dict:
    """Given a YARA-L time_window string (e.g. '30m', '1h', '24h'), estimate the
    Chronicle cadence and the worst-case wait before the composite can fire."""
    if not time_window:
        return {"cadence": "UNKNOWN", "max_wait_minutes": 60, "explanation": "No match window parsed — assume up to 1 hour."}
    tw = time_window.strip().lower()
    m = re.match(r"(\d+)\s*([smhd])", tw)
    if not m:
        return {"cadence": "UNKNOWN", "max_wait_minutes": 60, "explanation": f"Unparseable window '{time_window}' — assume up to 1 hour."}
    n, unit = int(m.group(1)), m.group(2)
    minutes = {"s": n / 60, "m": n, "h": n * 60, "d": n * 60 * 24}[unit]
    if minutes < 60:
        return {"cadence": "LIVE", "max_wait_minutes": 60, "explanation": "Window <1h → LIVE, but Chronicle's schedule still makes cascade evaluation take up to 1 hour."}
    if minutes < 60 * 24:
        return {"cadence": "HOURLY", "max_wait_minutes": 60, "explanation": "Window 1–24h → HOURLY cadence, next run within 1 hour."}
    return {"cadence": "DAILY", "max_wait_minutes": 60 * 24, "explanation": "Window ≥24h → DAILY cadence, next run within 24 hours."}


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
def generate_cascade_events(composite_analysis_json: str, base_rule_texts_json: str = "") -> str:
    """Given a composite rule analysis, generate a chained set of UDM events that fire each stage
    in sequence (or any order) with join_keys threaded through all of them.
    base_rule_texts_json: optional {name: rule_text} — when provided, each stage's events are
    generated against the actual base rule source, which is the only way the cascade actually fires.
    Returns {stages: [{stage_name, events}], all_events, count}."""
    try:
        analysis = json.loads(composite_analysis_json) if isinstance(composite_analysis_json, str) else composite_analysis_json
    except Exception:
        return json.dumps({"error": "Invalid composite_analysis_json"})

    base_rule_texts: dict = {}
    if base_rule_texts_json:
        try:
            base_rule_texts = json.loads(base_rule_texts_json) if isinstance(base_rule_texts_json, str) else base_rule_texts_json
        except Exception:
            return json.dumps({"error": "Invalid base_rule_texts_json"})

    stages = analysis.get("base_components", [])
    if not stages and not base_rule_texts:
        return json.dumps({"error": "No base_components in composite analysis and no base rule texts supplied"})

    join_keys = analysis.get("join_keys", [])
    ordering  = analysis.get("ordering", "sequential")
    now = datetime.now(timezone.utc)

    if base_rule_texts:
        base_section = "\n\n".join(
            f"=== Base rule: {name} ===\n{text}" for name, text in base_rule_texts.items()
        )
        stage_count = len(base_rule_texts)
        stage_names_hint = list(base_rule_texts.keys())
        prompt = f"""Generate RAW UDM telemetry events that cause each base rule below to fire. The composite rule correlates those base-rule detections, so we need the base rules to fire first.

CRITICAL: Generate raw UDM telemetry — event types like PROCESS_LAUNCH, NETWORK_CONNECTION, FILE_CREATION, USER_LOGIN, USER_UNCATEGORIZED, EMAIL_TRANSACTION, etc. DO NOT generate events with metadata.event_type = "DETECTION". DETECTION records are outputs of the SecOps rule engine, not inputs. Your events are ingested as raw telemetry; the engine then runs the base rules against them and emits its own DETECTION records.

For each base rule below, generate 1-3 UDM events that satisfy that rule's $eN field filters (metadata.event_type, network.*, principal.*, target.*, security_result.*, etc.). Each event must match the conditions in the `events {{ ... }}` section of the corresponding base rule.

Composite rule analysis (join keys, ordering, time window):
{json.dumps(analysis, indent=2)}

{base_section}

Hard rules:
- The entity values for these join_keys MUST be identical across every stage: {json.dumps(join_keys)}
  (e.g. same principal.user.userid, principal.hostname, and principal.ip across all stages)
- If ordering="sequential", stage N timestamps must be strictly earlier than stage N+1
- Timestamps start at {now.strftime('%Y-%m-%dT%H:%M:%S.000Z')} and are spaced 30-90 seconds apart across the whole cascade
- security_result[0].action MUST be "ALLOW" or "BLOCK" where present
- metadata.event_type MUST be a valid UDM type matched by the base rule (inspect each rule's $eN.metadata.event_type filter)
- Omit any DETECTION-shaped fields ($var.detection.*, outcomes, rule_name); those are composite concerns, not telemetry

Return ONLY this JSON, no markdown fences:
{{
  "stages": [
    {", ".join(f'{{"stage_name": "{n}", "events": [...raw UDM events that trigger {n}...]}}' for n in stage_names_hint)}
  ]
}}"""
    else:
        stage_count = len(stages)
        prompt = f"""Generate a CASCADE of UDM events that fires a composite detection in sequence.
The composite has {stage_count} stages; generate 1-3 events per stage.

CRITICAL: Generate raw UDM telemetry (PROCESS_LAUNCH, NETWORK_CONNECTION, FILE_CREATION, USER_LOGIN, etc.). DO NOT set metadata.event_type = "DETECTION". Detections are engine outputs; your events are telemetry inputs.

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
    """End-to-end composite validation: analyze → fetch base rule sources → generate cascade →
    ingest. Client polls each base rule + composite rule to confirm the cascade fires. Composite
    validation is SLOW — expect up to 1 hour for rules with match windows 1-24h, up to 24 hours
    for windows ≥24h.
    base_rule_names: comma-separated names of the base rules the composite depends on. Those
    rules MUST already be deployed LIVE in SecOps; the validator fetches their source to generate
    raw UDM that actually fires them."""
    try:
        analysis_raw = analyze_composite_rule(composite_rule_text)
        analysis = json.loads(analysis_raw)
        if "error" in analysis:
            return json.dumps({"status": "FAILED", "stage": "analyze", "analysis": analysis})

        wait_info = _estimate_composite_wait(analysis.get("time_window", ""))

        base_rules = [n.strip() for n in base_rule_names.split(",") if n.strip()]
        auto_detected = False
        if not base_rules:
            base_rules = _extract_base_rule_refs(composite_rule_text)
            auto_detected = bool(base_rules)
        base_rule_texts: dict = {}
        if base_rules:
            fetch = _fetch_rule_texts_by_name(base_rules)
            if fetch["missing"]:
                return json.dumps({
                    "status": "FAILED",
                    "stage": "fetch_base_rules",
                    "missing_rules": fetch["missing"],
                    "base_rule_names_resolved": base_rules,
                    "auto_detected": auto_detected,
                    "message": (
                        f"Base rules not deployed in SecOps: {fetch['missing']}. "
                        "Deploy them LIVE first — the composite can only fire when its base rules fire."
                    ),
                })
            base_rule_texts = fetch["found"]

        cascade_raw = generate_cascade_events(
            analysis_raw,
            base_rule_texts_json=json.dumps(base_rule_texts) if base_rule_texts else "",
        )
        cascade = json.loads(cascade_raw)
        if "error" in cascade:
            return json.dumps({"status": "FAILED", "stage": "cascade_generate", "cascade": cascade})

        events_payload = {"events": cascade["all_events"]}
        ingest_raw = ingest_synthetic_events(json.dumps(events_payload))
        ingest = json.loads(ingest_raw)
        if "error" in ingest:
            return json.dumps({"status": "FAILED", "stage": "ingest", "ingest": ingest})

        return json.dumps({
            "status": "INGESTED_AWAITING_CASCADE_VERIFY",
            "composite_rule_name": analysis.get("rule_name", ""),
            "base_rule_names": base_rules,
            "base_rule_names_auto_detected": auto_detected,
            "base_rules_used_for_generation": list(base_rule_texts.keys()),
            "stages": cascade["stages"],
            "stage_count": cascade["stage_count"],
            "event_count": cascade["count"],
            "validation_id": ingest.get("validation_id", ""),
            "analysis": analysis,
            "ingestion_time": ingest.get("ingestion_time", ""),
            "warning": _COMPOSITE_WARNING,
            "wait_estimate": wait_info,
            "next_step": f"Poll verify_rule_triggered for each of: [{', '.join(base_rules + [analysis.get('rule_name', 'composite')])}] on the cadence indicated by wait_estimate (up to {wait_info['max_wait_minutes']} minutes).",
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def composite_static_validate(composite_rule_text: str, wait_seconds: int = 120) -> str:
    """Fast path for composite rules in CI. Validates each referenced base
    rule end-to-end (synthetic events fire the base rule), plus runs a
    structural check on the composite itself (join keys, window, ordering).
    Skips the 1-24 hour Chronicle cascade wait. Returns one of:
      STATIC_OK                  every base rule fires; composite structure valid
      STATIC_FAIL_BASE_RULE      at least one base rule failed its own validation
      STATIC_FAIL_MISSING_BASES  composite references rules not deployed in SecOps
      STATIC_FAIL_STRUCTURE      composite is malformed (no joins, no window)
      NOT_COMPOSITE              rule is not a composite; caller should use run_full_validation

    This does NOT prove Chronicle will chain the cascade on its schedule. It
    proves the inputs to the cascade work; Chronicle's scheduler is a separate
    concern handled by cascade_validate (slow) or nightly jobs.
    """
    heuristic = _detect_composite(composite_rule_text)
    if not heuristic["is_composite"]:
        return json.dumps({
            "status": "NOT_COMPOSITE",
            "heuristic": heuristic,
            "message": "Rule is not composite. Use run_full_validation instead.",
        })

    analysis_raw = analyze_composite_rule(composite_rule_text)
    analysis = json.loads(analysis_raw)
    if "error" in analysis:
        return json.dumps({"status": "STATIC_FAIL_STRUCTURE", "stage": "analyze", "analysis": analysis})

    base_rules = _extract_base_rule_refs(composite_rule_text)
    if not base_rules:
        return json.dumps({
            "status": "STATIC_FAIL_STRUCTURE",
            "reason": "Composite references no base rule names by literal match.",
            "heuristic": heuristic,
            "analysis": analysis,
        })

    fetch = _fetch_rule_texts_by_name(base_rules)
    if fetch["missing"]:
        return json.dumps({
            "status": "STATIC_FAIL_MISSING_BASES",
            "missing_rules": fetch["missing"],
            "found_rules": list(fetch["found"].keys()),
            "message": (
                f"Composite references rules not deployed LIVE in SecOps: {fetch['missing']}. "
                "Deploy them first, then re-run."
            ),
        })

    structure_issues: list = []
    if not (analysis.get("join_keys") or []):
        structure_issues.append("No join_keys extracted from the composite.")
    if not analysis.get("time_window"):
        structure_issues.append("No match window parsed; cascade cannot correlate.")

    base_results: list = []
    overall_ok = True
    for name, text in fetch["found"].items():
        per = run_full_validation(text, rule_name=name, wait_seconds=wait_seconds)
        per_obj = json.loads(per)
        base_results.append({"rule_name": name, "status": per_obj.get("status"), "result": per_obj})
        if per_obj.get("status") not in ("INGESTED_AWAITING_VERIFICATION", "USE_CASCADE_VALIDATE"):
            overall_ok = False

    return json.dumps({
        "status": "STATIC_OK" if (overall_ok and not structure_issues) else "STATIC_FAIL_BASE_RULE" if not overall_ok else "STATIC_FAIL_STRUCTURE",
        "composite_rule_name": analysis.get("rule_name", ""),
        "base_rule_results": base_results,
        "structure_issues": structure_issues,
        "analysis": analysis,
        "note": (
            "Each base rule was ingested and will be verified by the caller's usual poll "
            "(see results[].result.next_step). Chronicle's cascade evaluation for the "
            "composite itself still happens on HOURLY/DAILY cadence and is not exercised here."
        ),
    })


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


@app.get("/api/metrics")
async def api_metrics(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return JSONResponse(metrics.snapshot())


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


@app.post("/api/generate-native")
async def api_generate_native(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    analysis_json = body.get("analysis_json", "")
    log_type = body.get("log_type", "").strip()
    count = int(body.get("count", 5))
    if not analysis_json or not log_type:
        return JSONResponse({"error": "analysis_json and log_type required"}, status_code=400)
    result = generate_native_log_events(analysis_json, log_type=log_type, count=count)
    return JSONResponse(json.loads(result))


@app.post("/api/ingest-native")
async def api_ingest_native(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    logs_json = body.get("logs_json", "")
    log_type = body.get("log_type", "").strip()
    if not logs_json or not log_type:
        return JSONResponse({"error": "logs_json and log_type required"}, status_code=400)
    result = ingest_native_logs(logs_json, log_type=log_type)
    return JSONResponse(json.loads(result))


@app.post("/api/validate")
async def api_validate(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    rule_text = body.get("rule", "").strip()
    rule_name = body.get("rule_name", "")
    validation_mode = body.get("validation_mode", "udm_direct")
    log_type = body.get("log_type", "")
    session_id = body.get("session_id") or request.cookies.get("yv_session") or str(uuid.uuid4())
    if not rule_text:
        return JSONResponse({"error": "No rule provided"}, status_code=400)
    result_raw = run_full_validation(rule_text, rule_name=rule_name, validation_mode=validation_mode, log_type=log_type)
    result = json.loads(result_raw)
    session_store.add_validation(session_id, {"ts": datetime.now(timezone.utc).isoformat(), **result})
    metrics.record_validation(result.get("rule_name") or rule_name, _outcome_bucket(result))
    resp = JSONResponse(result)
    resp.set_cookie("yv_session", session_id, max_age=86400, samesite="lax")
    return resp


@app.get("/api/log-types")
async def api_log_types(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return JSONResponse({
        "supported": [{"log_type": k, "description": v} for k, v in KNOWN_PARSER_LOG_TYPES.items()],
        "note": "Any Chronicle-supported log_type works; those listed above have Gemini hints. Others fall back to a generic native-format prompt.",
    })


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
    parsed = json.loads(result)
    if parsed.get("triggered") is True or parsed.get("status") == "FIRED":
        metrics.record_validation(rule_name, "PASS")
    elif parsed.get("status") in ("NOT_FIRED", "FAILED", "ERROR"):
        metrics.record_validation(rule_name, "FAIL")
    return JSONResponse(parsed)


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
    metrics.record_negative_test()
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
    metrics.record_fixture("save")
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
    metrics.record_fixture("load")
    return JSONResponse(json.loads(result))


@app.get("/api/fixture/list")
async def api_fixture_list(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    result = list_fixtures()
    return JSONResponse(json.loads(result))


# ── RULE LIBRARY ENDPOINTS ─────────────────────────────────────
@app.post("/api/rule/save")
async def api_rule_save(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    rule_name = body.get("rule_name", "")
    rule_text = body.get("rule_text", "")
    notes = body.get("notes", "")
    source = body.get("source", "user")
    if not rule_name or not rule_text:
        return JSONResponse({"error": "rule_name and rule_text required"}, status_code=400)
    result = save_rule(rule_name, rule_text, notes=notes, source=source)
    return JSONResponse(json.loads(result))


@app.post("/api/rule/load")
async def api_rule_load(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    rule_name = body.get("rule_name", "")
    if not rule_name:
        return JSONResponse({"error": "rule_name required"}, status_code=400)
    result = load_rule(rule_name)
    return JSONResponse(json.loads(result))


@app.get("/api/rule/list")
async def api_rule_list(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return JSONResponse(json.loads(list_saved_rules()))


@app.post("/api/rule/delete")
async def api_rule_delete(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    rule_name = body.get("rule_name", "")
    if not rule_name:
        return JSONResponse({"error": "rule_name required"}, status_code=400)
    return JSONResponse(json.loads(delete_saved_rule(rule_name)))


@app.post("/api/generate-rule")
async def api_generate_rule(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    description = body.get("description", "").strip()
    event_type_hint = body.get("event_type_hint", "")
    severity = body.get("severity", "MEDIUM")
    if not description:
        return JSONResponse({"error": "description required"}, status_code=400)
    result = generate_yara_l_rule(description, event_type_hint=event_type_hint, severity=severity)
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


@app.post("/api/composite-static-validate")
async def api_composite_static_validate(request: Request):
    if not _verify_google_token(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    rule_text = body.get("rule_text", body.get("rule", "")).strip()
    wait_seconds = int(body.get("wait_seconds", 120))
    if not rule_text:
        return JSONResponse({"error": "rule_text required"}, status_code=400)
    result = composite_static_validate(rule_text, wait_seconds=wait_seconds)
    parsed = json.loads(result)
    metrics.record_composite_static()
    metrics.record_validation(parsed.get("composite_rule_name", ""), _outcome_bucket(parsed))
    return JSONResponse(parsed)


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
            "- 'validate / test / run full test / end to end' → run_full_validation\n"
            "- 'generate/write/create a rule for X / build a rule that detects Y' → generate_yara_l_rule\n"
            "- 'save this rule / remember this rule' → save_rule\n"
            "- 'load rule X / use the saved rule X' → load_rule\n"
            "- 'list my saved rules / show me my rules' → list_saved_rules\n\n"
            "RULES:\n"
            "- When user pastes a YARA-L rule, always analyze it first with analyze_yara_l_rule\n"
            "- When user asks to create / generate a new rule, use generate_yara_l_rule, then ALSO call save_rule with source='ai-generated' so it shows up in the saved rules panel\n"
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
