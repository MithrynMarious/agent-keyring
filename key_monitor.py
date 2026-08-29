"""Key health monitor — tracks connectivity, rotation age, and staleness.

EPIC-KEYRING-220. Wraps connectivity_test.py with persistent health logging,
rotation detection via key hash comparison, and dashboard-ready output.

DC-1 SAFE: Key values are hashed (SHA-256) for rotation detection only.
No secret values are stored, logged, or printed.

Usage:
  python key_monitor.py                # run checks, log results, print status
  python key_monitor.py --status       # print latest status without re-checking
  python key_monitor.py --json         # output latest status as JSON
  python key_monitor.py --html         # generate self-contained HTML dashboard
  python key_monitor.py --history N    # show last N check summaries

Cross-platform: pure Python stdlib. Runs on Windows, macOS, Linux.
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _DIR)

from secret_store import LocalFileStore
from connectivity_test import SERVICE_CHECKS

HEALTH_LOG = os.path.join(_DIR, "health_log.jsonl")
HEALTH_STATUS = os.path.join(_DIR, "health_status.json")
KEY_ROTATION = os.path.join(_DIR, "key_rotation.json")
SECRETS_PATH = os.environ.get(
    "KEYRING_SECRET_STORE",
    os.path.join(_DIR, ".secrets.json"),
)

ROTATION_THRESHOLDS = {
    "bearer": 90,
    "oauth-client": 365,
    "service-account": 365,
    "encryption": 180,
    "jwt": 180,
    "url": None,
    "default": 90,
}

SECRET_CATEGORIES = {
    "agentmail-api-key": "bearer",
    "stripe-secret-key": "bearer",
    "stripe-publishable-key": "bearer",
    "firebase-sa-key": "service-account",
    "supabase-url": "url",
    "supabase-service-key": "bearer",
    "pkc-supabase-url": "url",
    "pkc-supabase-service-key": "bearer",
    "cf-crm-supabase-url": "url",
    "cf-crm-supabase-key": "bearer",
    "pinax-crypto-key": "encryption",
    "pinax-supabase-jwt-secret": "jwt",
    "pinax-google-client-secrets": "oauth-client",
    "ga4-credentials": "oauth-client",
    "google-oauth-578790412002": "oauth-client",
    "bifrost-discord-token": "bearer",
    "bifrost-claude-api-key": "bearer",
    "anthropic-api-key": "bearer",
    "huggingface-token": "bearer",
    "promptlabs-openai": "bearer",
    "promptlabs-google": "bearer",
    "promptlabs-aws-access-key": "bearer",
    "promptlabs-aws-secret-key": "bearer",
}

SVC_SECRET_MAP = {
    "agentmail": ["agentmail-api-key"],
    "stripe": ["stripe-secret-key"],
    "supabase": ["supabase-url", "supabase-service-key"],
    "supabase-pkc": ["pkc-supabase-url", "pkc-supabase-service-key"],
    "supabase-crm": ["cf-crm-supabase-url", "cf-crm-supabase-key"],
    "discord": ["bifrost-discord-token"],
    "anthropic": ["anthropic-api-key"],
    "anthropic-bifrost": ["bifrost-claude-api-key"],
    "openai": ["promptlabs-openai"],
    "google-ai": ["promptlabs-google"],
    "huggingface": ["huggingface-token"],
    "firebase": ["firebase-sa-key"],
    "ga4": ["ga4-credentials"],
    "google-oauth": ["google-oauth-578790412002"],
    "pinax-crypto": ["pinax-crypto-key"],
    "pinax-jwt": ["pinax-supabase-jwt-secret"],
    "pinax-google": ["pinax-google-client-secrets"],
    "aws": ["promptlabs-aws-access-key", "promptlabs-aws-secret-key"],
}


def _load_json(path, default=None):
    if not os.path.exists(path):
        return default if default is not None else {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _days_since(iso_date):
    if not iso_date:
        return None
    try:
        then = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - then).days
    except (ValueError, TypeError):
        return None


def update_rotation_tracking():
    """Compare current key hashes against stored hashes. DC-1 safe."""
    rotation = _load_json(KEY_ROTATION, {})
    store_data = _load_json(SECRETS_PATH, {})
    now = _now_iso()

    for name, value in store_data.items():
        if name.startswith("_") or not isinstance(value, str) or len(value) < 10:
            continue
        current_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()

        if name not in rotation:
            rotation[name] = {
                "hash": current_hash,
                "first_seen": now,
                "last_changed": now,
                "check_count": 1,
            }
        else:
            entry = rotation[name]
            entry["check_count"] = entry.get("check_count", 0) + 1
            if entry.get("hash") != current_hash:
                entry["hash"] = current_hash
                entry["last_changed"] = now

    _save_json(KEY_ROTATION, rotation)
    return rotation


def run_health_check(store):
    """Run all connectivity checks."""
    results = []
    for svc_key, (label, check_fn) in SERVICE_CHECKS.items():
        t0 = time.time()
        try:
            ok, detail = check_fn(store)
        except Exception as e:
            ok, detail = False, f"exception: {type(e).__name__}: {str(e)[:100]}"
        elapsed_ms = int((time.time() - t0) * 1000)
        results.append({
            "service": svc_key,
            "label": label,
            "status": "pass" if ok else "fail",
            "detail": detail,
            "response_ms": elapsed_ms,
        })
    return results


def log_results(results):
    """Append to health_log.jsonl."""
    now = _now_iso()
    entry = {
        "timestamp": now,
        "results": results,
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r["status"] == "pass"),
            "failed": sum(1 for r in results if r["status"] == "fail"),
        },
    }
    with open(HEALTH_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")


def build_status(results, rotation):
    """Assemble comprehensive status report."""
    now = _now_iso()
    services = []

    for r in results:
        secrets = SVC_SECRET_MAP.get(r["service"], [])
        rot_info = []
        for secret_name in secrets:
            if secret_name in rotation:
                rot = rotation[secret_name]
                cat = SECRET_CATEGORIES.get(secret_name, "default")
                threshold = ROTATION_THRESHOLDS.get(cat, 90)
                age = _days_since(rot.get("last_changed"))
                rot_info.append({
                    "secret": secret_name,
                    "category": cat,
                    "age_days": age,
                    "threshold_days": threshold,
                    "needs_rotation": threshold is not None and age is not None and age > threshold,
                    "last_changed": rot.get("last_changed"),
                })

        if r["status"] == "fail" and "not found" in r["detail"]:
            health = "empty"
        elif r["status"] == "fail":
            health = "failing"
        elif any(ri.get("needs_rotation") for ri in rot_info):
            health = "stale"
        else:
            health = "healthy"

        services.append({
            "service": r["service"],
            "label": r["label"],
            "connectivity": r["status"],
            "detail": r["detail"],
            "response_ms": r["response_ms"],
            "health": health,
            "rotation": rot_info,
        })

    summary = {
        "total": len(services),
        "healthy": sum(1 for s in services if s["health"] == "healthy"),
        "stale": sum(1 for s in services if s["health"] == "stale"),
        "failing": sum(1 for s in services if s["health"] == "failing"),
        "empty": sum(1 for s in services if s["health"] == "empty"),
    }

    return {"timestamp": now, "summary": summary, "services": services}


def print_status(status):
    """Human-readable status."""
    s = status["summary"]
    print("KEY HEALTH MONITOR")
    print("=" * 65)
    print(f"  Checked: {status['timestamp']}")
    print(f"  Healthy: {s['healthy']}  Stale: {s['stale']}  "
          f"Failing: {s['failing']}  Empty: {s['empty']}")
    print()

    for svc in status["services"]:
        icons = {"healthy": " OK ", "stale": "AGE", "failing": "FAIL", "empty": " -- "}
        icon = icons.get(svc["health"], "???")
        line = f"  [{icon}] {svc['label']:28s} {svc['detail']}"
        if svc["response_ms"]:
            line += f" ({svc['response_ms']}ms)"
        print(line)
        for ri in svc.get("rotation", []):
            if ri.get("age_days") is not None and ri.get("threshold_days"):
                flag = " << ROTATE" if ri["needs_rotation"] else ""
                print(f"         key age: {ri['age_days']}d / "
                      f"{ri['threshold_days']}d threshold ({ri['category']}){flag}")

    print(f"\n{'=' * 65}")


def print_history(n=5):
    """Show last N check summaries from the log."""
    if not os.path.exists(HEALTH_LOG):
        print("No health log found. Run a check first.")
        return
    lines = []
    with open(HEALTH_LOG, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                lines.append(line)
    if not lines:
        print("Health log is empty.")
        return

    print(f"HEALTH CHECK HISTORY (last {n})")
    print("=" * 65)
    for raw in lines[-n:]:
        try:
            entry = json.loads(raw)
            s = entry["summary"]
            ts = entry["timestamp"]
            print(f"  {ts}  pass:{s['passed']} fail:{s['failed']} total:{s['total']}")
        except (json.JSONDecodeError, KeyError):
            continue
    print(f"{'=' * 65}")
    print(f"  Log file: {HEALTH_LOG}")
    print(f"  Total entries: {len(lines)}")


def generate_html(status):
    """Generate self-contained HTML dashboard. Returns the HTML string."""
    data_json = json.dumps(status, indent=2)
    s = status["summary"]

    svc_rows = []
    for svc in status["services"]:
        rot_lines = []
        for ri in svc.get("rotation", []):
            if ri.get("age_days") is not None and ri.get("threshold_days"):
                pct = min(100, int(ri["age_days"] / ri["threshold_days"] * 100))
                rot_lines.append(
                    f'<div class="rot-bar"><div class="rot-fill'
                    f'{" rot-warn" if pct > 80 else ""}" '
                    f'style="width:{pct}%"></div>'
                    f'<span>{ri["age_days"]}d / {ri["threshold_days"]}d</span></div>'
                )
        rot_html = "\n".join(rot_lines) if rot_lines else ""

        svc_rows.append(f"""
        <tr class="svc-row {svc['health']}">
          <td><span class="dot {svc['health']}"></span></td>
          <td class="svc-label">{svc['label']}</td>
          <td class="svc-detail">{svc['detail']}</td>
          <td class="svc-ms">{svc['response_ms']}ms</td>
          <td class="svc-rot">{rot_html}</td>
        </tr>""")

    rows_html = "\n".join(svc_rows)
    ts = status["timestamp"]

    return f"""<title>Keyring Health</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&display=swap">
<style>
  :root {{
    --bg: #fafaf9; --fg: #1c1917; --card: #ffffff; --border: #e7e5e4;
    --muted: #78716c; --green: #16a34a; --yellow: #ca8a04; --red: #dc2626;
    --empty: #a8a29e; --bar-bg: #e7e5e4; --bar-fill: #16a34a; --bar-warn: #ca8a04;
  }}
  @media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
      --bg: #1c1917; --fg: #fafaf9; --card: #292524; --border: #44403c;
      --muted: #a8a29e; --bar-bg: #44403c;
    }}
  }}
  :root[data-theme="dark"] {{
    --bg: #1c1917; --fg: #fafaf9; --card: #292524; --border: #44403c;
    --muted: #a8a29e; --bar-bg: #44403c;
  }}

  body {{
    background: var(--bg); color: var(--fg);
    font-family: "IBM Plex Mono", "SF Mono", "Cascadia Code", monospace;
    margin: 0; padding: 2rem; max-width: 960px; margin-inline: auto;
  }}
  h1 {{ font-size: 1.25rem; font-weight: 600; margin: 0 0 0.25rem; }}
  .ts {{ color: var(--muted); font-size: 0.8rem; margin-bottom: 1.5rem; }}

  .summary {{
    display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap;
  }}
  .stat {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 6px; padding: 0.75rem 1.25rem; min-width: 100px;
    text-align: center;
  }}
  .stat .num {{ font-size: 1.75rem; font-weight: 700; line-height: 1; }}
  .stat .lbl {{ font-size: 0.7rem; text-transform: uppercase; color: var(--muted);
    letter-spacing: 0.05em; margin-top: 0.25rem; }}
  .stat.healthy .num {{ color: var(--green); }}
  .stat.stale .num {{ color: var(--yellow); }}
  .stat.failing .num {{ color: var(--red); }}
  .stat.empty .num {{ color: var(--empty); }}

  table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
  th {{
    text-align: left; font-size: 0.7rem; text-transform: uppercase;
    color: var(--muted); letter-spacing: 0.05em; padding: 0.5rem 0.5rem;
    border-bottom: 2px solid var(--border);
  }}
  td {{ padding: 0.6rem 0.5rem; border-bottom: 1px solid var(--border); vertical-align: top; }}

  .dot {{
    display: inline-block; width: 10px; height: 10px; border-radius: 50%;
  }}
  .dot.healthy {{ background: var(--green); }}
  .dot.stale {{ background: var(--yellow); }}
  .dot.failing {{ background: var(--red); }}
  .dot.empty {{ background: var(--empty); }}

  .svc-label {{ font-weight: 500; white-space: nowrap; }}
  .svc-detail {{ color: var(--muted); max-width: 280px; }}
  .svc-ms {{ color: var(--muted); text-align: right; white-space: nowrap; }}

  .rot-bar {{
    position: relative; height: 14px; background: var(--bar-bg);
    border-radius: 3px; overflow: hidden; min-width: 80px; margin: 2px 0;
  }}
  .rot-fill {{
    height: 100%; background: var(--bar-fill); border-radius: 3px;
    transition: width 0.3s;
  }}
  .rot-fill.rot-warn {{ background: var(--bar-warn); }}
  .rot-bar span {{
    position: absolute; top: 0; right: 4px; font-size: 0.65rem;
    line-height: 14px; color: var(--fg); opacity: 0.7;
  }}

  .footer {{
    margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border);
    font-size: 0.7rem; color: var(--muted);
  }}

  @media (max-width: 640px) {{
    body {{ padding: 1rem; }}
    .summary {{ gap: 0.5rem; }}
    .stat {{ min-width: 70px; padding: 0.5rem 0.75rem; }}
    .svc-ms, .svc-rot {{ display: none; }}
  }}
</style>

<h1>Keyring Health</h1>
<div class="ts">Last checked: {ts}</div>

<div class="summary">
  <div class="stat healthy"><div class="num">{s['healthy']}</div><div class="lbl">Healthy</div></div>
  <div class="stat stale"><div class="num">{s['stale']}</div><div class="lbl">Stale</div></div>
  <div class="stat failing"><div class="num">{s['failing']}</div><div class="lbl">Failing</div></div>
  <div class="stat empty"><div class="num">{s['empty']}</div><div class="lbl">Empty</div></div>
</div>

<table>
  <thead>
    <tr><th></th><th>Service</th><th>Detail</th><th style="text-align:right">Latency</th><th>Key Age</th></tr>
  </thead>
  <tbody>
    {rows_html}
  </tbody>
</table>

<div class="footer">
  Agent Keyring &middot; CoreForged LLC &middot; Generated by key_monitor.py<br>
  Re-run <code>python key_monitor.py --html</code> to refresh.
</div>

<script>
  const data = {data_json};
  console.log("Keyring health data:", data);
</script>
"""


def cmd_run(args):
    """Default: run checks, update rotation, log, print status."""
    if not os.path.exists(SECRETS_PATH):
        print(f"Secret store not found: {SECRETS_PATH}")
        print("Run populate_secrets.py --write first, or set KEYRING_SECRET_STORE.")
        sys.exit(1)

    store = LocalFileStore(SECRETS_PATH)
    rotation = update_rotation_tracking()
    results = run_health_check(store)
    log_results(results)
    status = build_status(results, rotation)
    _save_json(HEALTH_STATUS, status)
    print_status(status)
    return status


def cmd_status():
    """Print latest status without re-checking."""
    status = _load_json(HEALTH_STATUS)
    if not status:
        print("No status file found. Run `python key_monitor.py` first.")
        sys.exit(1)
    age = _days_since(status.get("timestamp"))
    if age and age > 1:
        print(f"  WARNING: Status is {age} days old. Re-run to refresh.\n")
    print_status(status)


def cmd_json():
    """Output latest status as JSON."""
    status = _load_json(HEALTH_STATUS)
    if not status:
        print("{}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(status, indent=2))


def cmd_html(output_path=None):
    """Generate HTML dashboard."""
    status = _load_json(HEALTH_STATUS)
    if not status:
        print("No status file. Run `python key_monitor.py` first.")
        sys.exit(1)

    html = generate_html(status)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"Dashboard written to: {output_path}")
    else:
        out = os.path.join(_DIR, "dashboard.html")
        with open(out, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"Dashboard written to: {out}")


def main():
    p = argparse.ArgumentParser(
        description="Keyring health monitor — connectivity, rotation, staleness"
    )
    p.add_argument("--status", action="store_true",
                    help="Show latest status without re-checking")
    p.add_argument("--json", action="store_true",
                    help="Output status as JSON")
    p.add_argument("--html", nargs="?", const="", metavar="PATH",
                    help="Generate HTML dashboard (optional output path)")
    p.add_argument("--history", type=int, metavar="N",
                    help="Show last N check summaries")

    args = p.parse_args()

    if args.status:
        cmd_status()
    elif args.json:
        cmd_json()
    elif args.html is not None:
        cmd_html(args.html if args.html else None)
    elif args.history:
        print_history(args.history)
    else:
        cmd_run(args)


if __name__ == "__main__":
    main()
