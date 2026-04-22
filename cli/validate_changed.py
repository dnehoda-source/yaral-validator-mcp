"""validate_changed: run the YARA-L Validator against only the .yaral rules
that changed in a PR. Designed to be called from CI (GitHub Actions, Cloud Build,
Jenkins) but works fine locally.

Usage:
    python -m cli.validate_changed \
        --rules-dir rules/ \
        --validator-url https://yaral-validator.example.com \
        --base origin/main \
        --id-token $(gcloud auth print-identity-token) \
        --out results.json \
        --markdown results.md

Exit code is 0 if every validated rule passed, 1 otherwise. Rules that were not
changed vs the base ref are skipped. Rules that parse as composite (reference
other rules or `.detection.` fields) are reported as SKIPPED_COMPOSITE with a
note, since composite cascade validation takes up to 24 hours and is not
appropriate for a blocking PR check. Use the web UI or a nightly job for those.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable

import requests


COMPOSITE_PATTERNS = (
    r"\$[A-Za-z_][A-Za-z0-9_]*\.detection\.",
    r"\brule\s*=\s*\"",
    r"outcome\s*:\s*.*\$[A-Za-z_][A-Za-z0-9_]*\.detection\.",
)


@dataclass
class RuleResult:
    path: str
    rule_name: str = ""
    status: str = ""
    detail: str = ""
    validation_id: str = ""
    elapsed_s: float = 0.0


def _run(cmd: list[str], cwd: Path | None = None) -> str:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if p.returncode != 0:
        raise SystemExit(f"{' '.join(cmd)} failed: {p.stderr.strip()}")
    return p.stdout.strip()


def changed_files(base: str, rules_dir: Path, repo_root: Path) -> list[Path]:
    _run(["git", "-C", str(repo_root), "fetch", "--no-tags", "origin", base.split("/")[-1]])
    diff = _run(
        ["git", "-C", str(repo_root), "diff", "--name-only", "--diff-filter=AM", f"{base}...HEAD"],
    )
    paths: list[Path] = []
    for line in diff.splitlines():
        p = (repo_root / line).resolve()
        try:
            p.relative_to(rules_dir.resolve())
        except ValueError:
            continue
        if p.suffix in (".yaral", ".yara-l", ".yl"):
            paths.append(p)
    return paths


def is_composite(rule_text: str) -> bool:
    import re
    for pat in COMPOSITE_PATTERNS:
        if re.search(pat, rule_text):
            return True
    return False


def validate_one(
    rule_path: Path,
    validator_url: str,
    id_token: str,
    poll_seconds: int,
    verify_minutes_back: int,
) -> RuleResult:
    text = rule_path.read_text()
    res = RuleResult(path=str(rule_path))
    t0 = time.time()

    if is_composite(text):
        res.status = "SKIPPED_COMPOSITE"
        res.detail = "Composite rule detected. Validate via the web UI or a nightly job (up to 24h wait)."
        res.elapsed_s = round(time.time() - t0, 2)
        return res

    headers = {"Authorization": f"Bearer {id_token}"} if id_token else {}

    r = requests.post(
        f"{validator_url}/api/validate",
        json={"rule": text},
        headers=headers,
        timeout=180,
    )
    if r.status_code == 401:
        res.status = "UNAUTHORIZED"
        res.detail = "Validator rejected the ID token. Check audience and ALLOWED_EMAILS."
        res.elapsed_s = round(time.time() - t0, 2)
        return res
    if not r.ok:
        res.status = "ERROR"
        res.detail = f"HTTP {r.status_code}: {r.text[:300]}"
        res.elapsed_s = round(time.time() - t0, 2)
        return res

    data = r.json()
    rule_name = data.get("rule_name") or data.get("results", {}).get("analysis", {}).get("rule_name", "")
    res.rule_name = rule_name
    validation_id = data.get("validation_id", "")
    res.validation_id = validation_id

    if data.get("status") == "USE_CASCADE_VALIDATE":
        res.status = "SKIPPED_COMPOSITE"
        res.detail = "Server classified rule as composite."
        res.elapsed_s = round(time.time() - t0, 2)
        return res

    if data.get("status") != "INGESTED_AWAITING_VERIFICATION":
        res.status = data.get("status", "UNKNOWN")
        res.detail = json.dumps(data)[:500]
        res.elapsed_s = round(time.time() - t0, 2)
        return res

    deadline = time.time() + poll_seconds
    last_resp: dict = {}
    while time.time() < deadline:
        time.sleep(15)
        v = requests.post(
            f"{validator_url}/api/verify",
            json={
                "rule_name": rule_name,
                "validation_id": validation_id,
                "minutes_back": verify_minutes_back,
            },
            headers=headers,
            timeout=60,
        )
        if not v.ok:
            last_resp = {"http_status": v.status_code, "body": v.text[:300]}
            continue
        last_resp = v.json()
        if last_resp.get("triggered") is True or last_resp.get("status") == "FIRED":
            res.status = "PASS"
            res.detail = last_resp.get("summary", "Rule fired on synthetic events.")
            res.elapsed_s = round(time.time() - t0, 2)
            return res
        if last_resp.get("status") in ("NOT_FIRED", "FAILED", "ERROR"):
            break

    res.status = "FAIL"
    res.detail = last_resp.get("summary") or json.dumps(last_resp)[:500] or "No detection observed within poll window."
    res.elapsed_s = round(time.time() - t0, 2)
    return res


def render_markdown(results: Iterable[RuleResult], base: str) -> str:
    rows = list(results)
    if not rows:
        return f"No `.yaral` rules changed vs `{base}`."
    lines = [
        f"### YARA-L Validator results (vs `{base}`)",
        "",
        "| Rule | Status | Time (s) | Detail |",
        "|------|--------|----------|--------|",
    ]
    for r in rows:
        name = r.rule_name or Path(r.path).name
        detail = (r.detail or "").replace("|", "\\|").replace("\n", " ")
        if len(detail) > 180:
            detail = detail[:177] + "..."
        lines.append(f"| `{name}` | **{r.status}** | {r.elapsed_s} | {detail} |")
    failed = sum(1 for r in rows if r.status == "FAIL")
    passed = sum(1 for r in rows if r.status == "PASS")
    skipped = sum(1 for r in rows if r.status.startswith("SKIPPED"))
    errored = sum(1 for r in rows if r.status in ("ERROR", "UNAUTHORIZED", "UNKNOWN"))
    lines += ["", f"Summary: {passed} passed, {failed} failed, {skipped} skipped, {errored} errored."]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rules-dir", type=Path, required=True)
    ap.add_argument("--validator-url", default=os.getenv("VALIDATOR_URL", ""))
    ap.add_argument("--id-token", default=os.getenv("VALIDATOR_ID_TOKEN", ""))
    ap.add_argument("--base", default="origin/main", help="Git ref to diff against.")
    ap.add_argument("--repo-root", type=Path, default=Path.cwd())
    ap.add_argument("--poll-seconds", type=int, default=180, help="Max seconds to poll verify endpoint per rule.")
    ap.add_argument("--verify-minutes-back", type=int, default=15)
    ap.add_argument("--out", type=Path, default=Path("results.json"))
    ap.add_argument("--markdown", type=Path, default=None)
    ap.add_argument("--all", action="store_true", help="Validate every rule, not just changed ones.")
    args = ap.parse_args(argv)

    if not args.validator_url:
        print("error: --validator-url or VALIDATOR_URL env is required", file=sys.stderr)
        return 2

    if args.all:
        paths = sorted(p for p in args.rules_dir.rglob("*") if p.suffix in (".yaral", ".yara-l", ".yl"))
    else:
        paths = changed_files(args.base, args.rules_dir, args.repo_root)

    print(f"Validating {len(paths)} rule(s) against {args.validator_url}")
    results: list[RuleResult] = []
    for p in paths:
        print(f"  -> {p}")
        results.append(validate_one(
            p,
            args.validator_url,
            args.id_token,
            args.poll_seconds,
            args.verify_minutes_back,
        ))

    args.out.write_text(json.dumps([asdict(r) for r in results], indent=2))
    if args.markdown:
        args.markdown.write_text(render_markdown(results, args.base))

    any_failed = any(r.status in ("FAIL", "ERROR", "UNAUTHORIZED") for r in results)
    print(f"Wrote {args.out}" + (f" and {args.markdown}" if args.markdown else ""))
    return 1 if any_failed else 0


if __name__ == "__main__":
    sys.exit(main())
