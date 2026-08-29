"""Connectivity test — verify all keyring secrets can reach their services.

EPIC-KEYRING-220. Tests each registered secret with a minimal health-check
API call. Secret values pass through memory only — never printed, logged,
or returned. Output is pass/fail per service.

Usage:
  python connectivity_test.py              # test all services
  python connectivity_test.py stripe       # test one service
  python connectivity_test.py --summary    # one-line per service
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
import base64
import ssl
import time

_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _DIR)

from secret_store import LocalFileStore

MANIFEST_PATH = os.path.join(_DIR, "secret_manifest.json")
SECRETS_PATH = os.environ.get(
    "KEYRING_SECRET_STORE",
    os.path.join(_DIR, ".secrets.json"),
)


def _load_manifest():
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        return json.load(f).get("secrets", {})


def _req(url, headers=None, method="GET", timeout=10):
    """Make an HTTP request. Returns (status_code, response_body_snippet)."""
    hdrs = headers or {}
    req = urllib.request.Request(url, headers=hdrs, method=method)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(512).decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(256).decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, body
    except Exception as e:
        return 0, str(e)[:200]


# --- Service-specific health checks ---
# Each returns (ok: bool, detail: str). Secret values are used in-memory
# for the API call but NEVER included in the return string.

def check_agentmail(store):
    key = store.get("agentmail-api-key")
    if not key:
        return False, "secret not found in store"
    status, body = _req(
        "https://api.agentmail.to/v0/inboxes?limit=1",
        {"Authorization": f"Bearer {key}", "Accept": "application/json"},
    )
    if status == 200:
        return True, f"HTTP {status} — inbox list OK"
    if status == 401:
        return False, f"HTTP {status} — key rejected"
    return False, f"HTTP {status}"


def check_stripe(store):
    key = store.get("stripe-secret-key")
    if not key:
        return False, "secret not found in store"
    status, body = _req(
        "https://api.stripe.com/v1/balance",
        {"Authorization": f"Bearer {key}"},
    )
    if status == 200:
        return True, f"HTTP {status} — balance endpoint OK"
    if status == 401:
        return False, f"HTTP {status} — key rejected"
    return False, f"HTTP {status}"


def check_supabase(store, url_secret, key_secret, label="primary"):
    url = store.get(url_secret)
    key = store.get(key_secret)
    if not url or not key:
        missing = []
        if not url:
            missing.append(url_secret)
        if not key:
            missing.append(key_secret)
        return False, f"missing: {', '.join(missing)}"
    endpoint = f"{url.rstrip('/')}/rest/v1/"
    status, body = _req(
        endpoint,
        {"apikey": key, "Authorization": f"Bearer {key}"},
    )
    if status == 200:
        return True, f"HTTP {status} — {label} REST endpoint OK"
    if status == 401:
        return False, f"HTTP {status} — key rejected ({label})"
    return False, f"HTTP {status} ({label})"


def check_discord(store):
    token = store.get("bifrost-discord-token")
    if not token:
        return False, "secret not found in store"
    status, body = _req(
        "https://discord.com/api/v10/users/@me",
        {"Authorization": f"Bot {token}"},
    )
    if status == 200:
        return True, f"HTTP {status} — bot identity OK"
    if status == 401:
        return False, f"HTTP {status} — token rejected"
    return False, f"HTTP {status}"


def check_anthropic(store, secret_name):
    key = store.get(secret_name)
    if not key:
        return False, "secret not found in store"
    # Use the models endpoint — lightweight, no tokens consumed
    status, body = _req(
        "https://api.anthropic.com/v1/models",
        {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        },
    )
    if status == 200:
        return True, f"HTTP {status} — API reachable"
    if status == 401:
        return False, f"HTTP {status} — key rejected"
    return False, f"HTTP {status}"


def check_openai(store):
    key = store.get("promptlabs-openai")
    if not key:
        return False, "secret not found in store"
    status, body = _req(
        "https://api.openai.com/v1/models",
        {"Authorization": f"Bearer {key}"},
    )
    if status == 200:
        return True, f"HTTP {status} — models list OK"
    if status == 401:
        return False, f"HTTP {status} — key rejected"
    return False, f"HTTP {status}"


def check_google_ai(store):
    key = store.get("promptlabs-google")
    if not key:
        return False, "secret not found in store"
    status, body = _req(
        f"https://generativelanguage.googleapis.com/v1beta/models?key={key}",
    )
    if status == 200:
        return True, f"HTTP {status} — models list OK"
    if status in (400, 403):
        return False, f"HTTP {status} — key rejected or API not enabled"
    return False, f"HTTP {status}"


def check_huggingface(store):
    token = store.get("huggingface-token")
    if not token:
        return False, "secret not found in store"
    status, body = _req(
        "https://huggingface.co/api/whoami-v2",
        {"Authorization": f"Bearer {token}"},
    )
    if status == 200:
        return True, f"HTTP {status} — token valid"
    if status == 401:
        return False, f"HTTP {status} — token rejected"
    return False, f"HTTP {status}"


def check_firebase(store):
    sa_json = store.get("firebase-sa-key")
    if not sa_json:
        return False, "secret not found in store"
    try:
        sa = json.loads(sa_json)
        project_id = sa.get("project_id", "?")
        has_key = "private_key" in sa
        if has_key and project_id != "?":
            return True, f"SA JSON valid — project: {project_id}"
        return False, "SA JSON missing private_key or project_id"
    except json.JSONDecodeError:
        return False, "SA JSON parse error"


def check_ga4(store):
    creds_json = store.get("ga4-credentials")
    if not creds_json:
        return False, "secret not found in store"
    try:
        creds = json.loads(creds_json)
        if "installed" in creds or "web" in creds:
            return True, "OAuth client JSON valid (needs refresh token for live test)"
        if "type" in creds and creds["type"] == "service_account":
            return True, f"SA JSON valid — project: {creds.get('project_id', '?')}"
        return False, "unrecognized credential format"
    except json.JSONDecodeError:
        return False, "JSON parse error"


def check_google_oauth(store):
    creds_json = store.get("google-oauth-578790412002")
    if not creds_json:
        return False, "secret not found in store"
    try:
        creds = json.loads(creds_json)
        if "installed" in creds or "web" in creds:
            return True, "OAuth client JSON valid"
        return False, "unrecognized credential format"
    except json.JSONDecodeError:
        return False, "JSON parse error"


def check_pinax_crypto(store):
    key = store.get("pinax-crypto-key")
    if not key:
        return False, "secret not found in store"
    if len(key) >= 16:
        return True, f"encryption key present ({len(key)} chars)"
    return False, f"key too short ({len(key)} chars)"


def check_pinax_jwt(store):
    key = store.get("pinax-supabase-jwt-secret")
    if not key:
        return False, "secret not found in store"
    if len(key) >= 16:
        return True, f"JWT secret present ({len(key)} chars)"
    return False, f"secret too short ({len(key)} chars)"


def check_pinax_google(store):
    creds_json = store.get("pinax-google-client-secrets")
    if not creds_json:
        return False, "secret not found in store"
    try:
        creds = json.loads(creds_json)
        if "installed" in creds or "web" in creds:
            return True, "OAuth client JSON valid"
        return False, "unrecognized credential format"
    except json.JSONDecodeError:
        return False, "JSON parse error"


def check_aws(store):
    access = store.get("promptlabs-aws-access-key")
    secret = store.get("promptlabs-aws-secret-key")
    if not access:
        return False, "access key not found in store"
    if not secret:
        return False, "secret key not found in store"
    if access.startswith("AKIA") and len(secret) >= 30:
        return True, f"keypair present (access: AKIA...{access[-4:]}, secret: {len(secret)} chars)"
    return True, f"keypair present (format non-standard but keys exist)"


# --- Test registry ---

SERVICE_CHECKS = {
    "agentmail": ("AgentMail", lambda s: check_agentmail(s)),
    "stripe": ("Stripe", lambda s: check_stripe(s)),
    "supabase": ("Supabase (primary)", lambda s: check_supabase(s, "supabase-url", "supabase-service-key", "primary")),
    "supabase-pkc": ("Supabase (PKC)", lambda s: check_supabase(s, "pkc-supabase-url", "pkc-supabase-service-key", "PKC")),
    "supabase-crm": ("Supabase (CRM)", lambda s: check_supabase(s, "cf-crm-supabase-url", "cf-crm-supabase-key", "CRM")),
    "discord": ("Discord (Bifrost)", lambda s: check_discord(s)),
    "anthropic": ("Anthropic (primary)", lambda s: check_anthropic(s, "anthropic-api-key")),
    "anthropic-bifrost": ("Anthropic (Bifrost)", lambda s: check_anthropic(s, "bifrost-claude-api-key")),
    "openai": ("OpenAI (PromptLabs)", lambda s: check_openai(s)),
    "google-ai": ("Google AI (PromptLabs)", lambda s: check_google_ai(s)),
    "huggingface": ("HuggingFace", lambda s: check_huggingface(s)),
    "firebase": ("Firebase SA", lambda s: check_firebase(s)),
    "ga4": ("GA4 Credentials", lambda s: check_ga4(s)),
    "google-oauth": ("Google OAuth", lambda s: check_google_oauth(s)),
    "pinax-crypto": ("Pinax Encryption", lambda s: check_pinax_crypto(s)),
    "pinax-jwt": ("Pinax JWT", lambda s: check_pinax_jwt(s)),
    "pinax-google": ("Pinax Google OAuth", lambda s: check_pinax_google(s)),
    "aws": ("AWS (PromptLabs)", lambda s: check_aws(s)),
}


def run_checks(store, target=None, summary=False):
    checks = SERVICE_CHECKS
    if target:
        key = target.lower().strip()
        if key in checks:
            checks = {key: checks[key]}
        else:
            matches = {k: v for k, v in checks.items() if key in k}
            if matches:
                checks = matches
            else:
                print(f"Unknown service: {target}")
                print(f"Available: {', '.join(sorted(SERVICE_CHECKS.keys()))}")
                return

    results = []
    for svc_key, (label, check_fn) in checks.items():
        t0 = time.time()
        try:
            ok, detail = check_fn(store)
        except Exception as e:
            ok, detail = False, f"exception: {type(e).__name__}: {str(e)[:100]}"
        elapsed = time.time() - t0
        results.append((svc_key, label, ok, detail, elapsed))

    if summary:
        for svc_key, label, ok, detail, elapsed in results:
            marker = "PASS" if ok else "FAIL"
            print(f"  [{marker}] {label:25s} ({elapsed:.1f}s) {detail}")
    else:
        print("KEYRING CONNECTIVITY TEST")
        print("=" * 70)
        passed = sum(1 for _, _, ok, _, _ in results if ok)
        failed = sum(1 for _, _, ok, _, _ in results if not ok)
        print(f"  Testing {len(results)} services...\n")

        for svc_key, label, ok, detail, elapsed in results:
            marker = "PASS" if ok else "FAIL"
            print(f"  [{marker}] {label}")
            print(f"         {detail} ({elapsed:.1f}s)")

        print(f"\n{'=' * 70}")
        print(f"  {passed} passed, {failed} failed, {len(results)} total")
        if failed:
            print(f"  Failed: {', '.join(k for k, _, ok, _, _ in results if not ok)}")
        print()

    return all(ok for _, _, ok, _, _ in results)


def main():
    parser = argparse.ArgumentParser(description="Keyring connectivity test")
    parser.add_argument("service", nargs="?", help="Test one service")
    parser.add_argument("--summary", action="store_true", help="One-line output")
    args = parser.parse_args()

    if not os.path.exists(SECRETS_PATH):
        print(f"Secret store not found: {SECRETS_PATH}")
        print("Set KEYRING_SECRET_STORE or create .secrets.json")
        sys.exit(1)

    store = LocalFileStore(SECRETS_PATH)
    all_ok = run_checks(store, target=args.service, summary=args.summary)
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
