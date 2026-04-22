# YARA-L Construct Coverage Matrix

This document lists which YARA-L language constructs the Validator can actually
reason about today, so detection teams know what's covered before trusting the
tool on a large rule library.

The Validator has two layers:

- **Analyzer** (`analyze_yara_l_rule`): extracts trigger conditions, event
  types, entity joins, count requirements, and time windows.
- **Generator** (`generate_synthetic_events`): produces UDM events that should
  satisfy what the Analyzer extracted.

Both run through Gemini, so constructs marked "implicit (via Gemini)" work in
practice but are not guaranteed by explicit code paths. Tighten those over time
by adding fixtures and regression tests.

## Legend

| Symbol | Meaning |
|--------|---------|
| OK      | First-class support with explicit code path in the Analyzer / Generator / Sanitizer. |
| Implicit | Works in practice via Gemini; no explicit code path. Behavior may drift with model updates. Pin with fixtures for critical rules. |
| Partial | Supported for common cases but edge cases may fall through. |
| Not yet | Not supported today. |

## Rule structure

| Construct | Status | Notes |
|-----------|--------|-------|
| `rule <name> { ... }` declaration | OK | Analyzer extracts name via regex, not from `meta.name`. |
| `meta` block | Implicit | Read by Gemini; not used programmatically. |
| `events` block, single event (`$e`) | OK | Core happy path. |
| `events` block, multi-event (`$e1`, `$e2`, ...) | OK | Analyzer extracts each variable and emits per-variable event counts. |
| `match` block with entity joins (`$e1.principal.ip = $e2.target.ip`) | OK | Emitted to `entity_joins`; generator enforces identical values across events. |
| `match ... over Nm / Nh / Nd` time window | OK | Parsed; generator spreads synthetic timestamps across a 9-minute window. Only the parsed value is surfaced. |
| `condition` block, simple `$e` | OK | |
| `condition` block with `#e >= N` count thresholds | OK | Analyzer extracts `min_event_count` and `event_breakdown`. |
| `condition` block with boolean combinators (`and`, `or`, `not`) | Implicit | Gemini generates events it believes satisfy the combined expression; no SAT solver. |
| `outcome` block | Implicit | Outcome assignments are read but not explicitly validated to produce the expected values. |

## Event field matchers

| Construct | Status | Notes |
|-----------|--------|-------|
| Exact string equality (`$e.principal.user.userid = "alice"`) | OK | Generator copies the literal into the synthetic event. |
| Numeric comparison (`=`, `>`, `<`, `>=`, `<=`) | Partial | Scalar equality works; range constraints rely on Gemini producing values in range. |
| `nocase` modifier | Implicit | Lower-case passthrough in generated values; no case-variation test. |
| Regex match (`re`) | Implicit | Gemini attempts to generate a matching literal; not validated against the regex. |
| IP CIDR match | Implicit | No CIDR-aware sampling; Gemini picks an IP it believes is in-range. |
| `in` list containment | Implicit | Gemini picks the first element; no coverage of other list members. |
| Reference list (`%ioc_list.<key>`) | Not yet | No mechanism to hydrate reference-list membership in generated events. Validate rules that depend on reference lists against real data. |

## UDM field coverage

The sanitizer (`_sanitize_udm_event`) enforces a top-level whitelist:

`metadata, principal, target, src, observer, about, intermediary, security_result, network, authentication, additional, extracted, extensions`

Any other top-level field is stripped before ingestion. `metadata.event_type`
is normalized against 87 valid UDM enums plus an alias table for common Gemini
mistakes (e.g. `PROCESS_ACTIVITY` → `PROCESS_LAUNCH`, `LOGIN` → `USER_LOGIN`,
`DNS_QUERY` → `NETWORK_DNS`).

Known-failing fields the sanitizer strips:

- `process.pid` across `principal`, `target`, `src` (uint32 schema, Gemini often emits strings).
- `metadata.id` (SDK generates a valid UUID).
- `metadata.ingestion_labels` (causes ingestion failures).
- `extensions` on generated events (frequent schema mismatches).
- `extracted_fields` (flat) remapped to `extracted.fields` (nested).

Fields explicitly supported in the generator prompt template:

- `metadata.event_timestamp`, `metadata.event_type`, `metadata.product_name`
- `principal.ip` (array), `principal.user.userid`, `principal.hostname`, `principal.process.command_line`
- `target.ip` (array), `target.user.userid`, `target.hostname`, `target.application`
- `security_result[].action` as `["ALLOW"]` or `["BLOCK"]`

Anything else relies on Gemini following the analyzed rule requirements.

## Composite rules

| Construct | Status | Notes |
|-----------|--------|-------|
| Composite detection (`$v.detection.detection.rule_name = "..."`) | OK (slow) | Detected by `_detect_composite`; routed to cascade flow. Validation takes up to 1h (HOURLY cadence, match window 1-24h) or up to 24h (DAILY cadence, window ≥24h) because Chronicle schedules composite evaluation and retrohunts don't work on composites. |
| `rule_name in ["a", "b", ...]` lists | OK | Extracted by `_extract_base_rule_refs`. |
| Base-rule source auto-fetch | OK | `_fetch_rule_texts_by_name` pulls deployed rule text from SecOps so the generator produces chained events against real base-rule signatures. |
| Composite with zero deployed base rules | Partial | Generator falls back to heuristics when base-rule text cannot be fetched; cascade may not fire. |

**CI note:** `cli/validate_changed.py` now has two composite modes (select with `--composite-mode`):

- `static` (default): route composites to `composite_static_validate`, which validates every referenced base rule end-to-end plus a structural check on the composite (join keys, window, ordering). Returns immediately. Does NOT exercise Chronicle's cascade scheduler.
- `skip`: mark every composite `SKIPPED_COMPOSITE` without any validation.

For full coverage, combine `--composite-mode static` in CI with a nightly
`cascade_validate` job that accepts the 1-24 hour wait.

## Negative testing coverage

`generate_negative_events` perturbs exactly five axes per rule. It does not
enumerate all possible false-positive classes.

| Axis | What it perturbs |
|------|------------------|
| Threshold | Generates N-1 events when the rule requires N. |
| Entity | Breaks the entity-join key (different users / IPs / hosts across events). |
| Time window | Spreads events outside the rule's match window. |
| Action | Flips `security_result.action` so the rule's action filter rejects. |
| Missing event type | Substitutes an adjacent but non-matching event type. |

If a rule has a false-positive class these axes don't cover (specific regex
edge cases, CIDR boundaries, reference-list misses), you will need a custom
fixture.

## Ingestion path

The Validator supports two ingestion paths, selectable per validation
(UI dropdown, `--validation-mode` flag, or `validation_mode` parameter).

### udm_direct (default, fast)

Uses `ingest_log(log_type=UDM)` so Chronicle's parser is skipped entirely.

- **Speed:** 60-120s to verdict.
- **Proves:** the rule's UDM conditions match a well-formed UDM event.
- **Does NOT prove:** your production parser produces the UDM shape the rule
  expects. A rule validated here can still fail in production if the parser
  maps fields differently (e.g. `principal.user.userid` vs
  `principal.user.email_addresses`).

### parser_path (slow, full-pipeline)

Generates raw native logs in the source format (Windows Event Log XML, Okta
JSON, GCP Cloud Audit JSON, Sysmon, CrowdStrike, CISCO_ASA, LINUX_SYSLOG,
O365, AWS_CLOUDTRAIL, Azure AD) and calls `ingest_log(log_type=<specific>)`.

- **Speed:** parser latency 30s-5min plus rule eval; budget 5+ minutes.
- **Proves:** the full ingest path. Parser converts native payload to UDM;
  rule evaluates against the parsed result. Catches parser-vs-rule mismatches
  the udm_direct path cannot see.
- **Requires:** `log_type` parameter (any Chronicle-supported type works;
  `KNOWN_PARSER_LOG_TYPES` in `main.py` has Gemini hints for common ones).
  Logs that fall outside those 10 types still work but the generator falls
  back to a generic native-format prompt, so expect lower fidelity until a
  hint is added.

### both

Runs udm_direct first, then parser_path. Returns both verdicts so the caller
can gate on either. Use for release-grade validation of critical rules.

### Caveat

Parser path validates against whatever parser is currently deployed to your
SecOps tenant. If you edit the parser, invalidate any cached fixtures or
re-run.

## Gaps we know about

- **No SAT-level condition solver.** Boolean combinators with mutually
  exclusive branches may confuse the generator.
- **No reference-list hydration.** Rules that match on `%list.<key>` need
  real data or custom fixtures.
- **No regex/CIDR-aware event sampling.** Coverage is best-effort via Gemini.
- **Per-rule determinism is opt-in.** Set `DETERMINISTIC=1` on the server to
  pin Gemini temperature to 0 and cache responses by
  `sha256(model, system, prompt, max_tokens)`. Identical rules then produce
  identical events within a server lifetime. Fixtures remain the durable path
  across restarts.
- **Parser path not tested.** See above.

Refresh this matrix whenever the analyzer prompt, generator prompt, or
sanitizer changes.
