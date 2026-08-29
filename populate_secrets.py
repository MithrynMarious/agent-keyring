"""Populate keyring .secrets.json from CrystallineCity/.secrets/ source files.

EPIC-KEYRING-220. Reads real credential values from the scattered source
files and writes them into the keyring's centralized secret store.

DC-1 SAFE: This script runs locally. Secret values pass through memory
only during the copy — they are never printed, logged, or sent anywhere.

Usage:
  python populate_secrets.py              # dry run — show what would be populated
  python populate_secrets.py --write      # write values to .secrets.json
  python populate_secrets.py --verify     # verify after write
"""

import argparse
import json
import os
import re
import sys

_DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS_JSON = os.path.join(_DIR, ".secrets.json")
SOURCE_DIR = os.environ.get(
    "KEYRING_SOURCE_DIR",
    os.path.normpath(os.path.join(_DIR, "..", "..", "..", ".secrets")),
)


def _read_env(path, key):
    """Read a specific key from a .env file."""
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k == key:
                return v
    return None


def _read_file(path):
    """Read entire file as string, stripped."""
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read().strip()


def _read_json_file(path):
    """Read a JSON file and return as compact JSON string."""
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return json.dumps(data, separators=(",", ":"))


def _read_pinax_key(path, line_index):
    """Read a specific line from pinax_keys.txt (0-indexed)."""
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = [l.strip() for l in f if l.strip()]
    if line_index < len(lines):
        val = lines[line_index]
        if len(val) > 10:
            return val
    return None


# --- Source mappings ---
# Maps keyring secret name -> (source_file_relative_to_.secrets, extraction_method)

SOURCE_MAP = {
    "agentmail-api-key": {
        "file": "agentmail.env",
        "extract": lambda: _read_env(_p("agentmail.env"), "AGENTMAIL_API_KEY")
                   or _read_file(_p("Agentmail api key.txt"))
                   or _read_file(_p("agentmail_api_key_Coreforged_agentmail_api_active.txt")),
    },
    "stripe-secret-key": {
        "file": "stripe.env",
        "extract": lambda: _read_env(_p("stripe.env"), "STRIPE_READ_KEY")
                   or _read_env(_p("stripe.env"), "STRIPE_SECRET_KEY"),
    },
    "stripe-publishable-key": {
        "file": "stripe.env",
        "extract": lambda: _read_env(_p("stripe.env"), "STRIPE_PUBLISHABLE_KEY"),
        "note": "stripe.env only has STRIPE_READ_KEY — publishable may need manual entry",
    },
    "firebase-sa-key": {
        "file": "coreforged-city-firebase-adminsdk-fbsvc-3937473483.JSON",
        "extract": lambda: _read_json_file(
            _p("coreforged-city-firebase-adminsdk-fbsvc-3937473483.JSON")),
    },
    "supabase-url": {
        "file": "supabase.env",
        "extract": lambda: _read_env(_p("supabase.env"), "SUPABASE_URL"),
    },
    "supabase-service-key": {
        "file": "supabase.env",
        "extract": lambda: _read_env(_p("supabase.env"), "SUPABASE_SERVICE_KEY")
                   or _read_env(_p("supabase.env"), "SUPABASE_KEY"),
    },
    "pkc-supabase-url": {
        "file": "clients/patternkindcollectiveSupabase.txt",
        "extract": lambda: _extract_supabase_url(
            _read_file(_p("clients/patternkindcollectiveSupabase.txt"))),
    },
    "pkc-supabase-service-key": {
        "file": "clients/patternkindcollectiveSupabase.txt",
        "extract": lambda: _extract_supabase_key(
            _read_file(_p("clients/patternkindcollectiveSupabase.txt"))),
    },
    "cf-crm-supabase-url": {
        "file": "PINAX.env",
        "extract": lambda: _read_env(_p("PINAX.env"), "SUPABASE_URL")
                   or _read_env(_p("PINAX.env"), "VITE_SUPABASE_URL")
                   or _read_env(_p("PINAX.env"), "CRM_SUPABASE_URL"),
    },
    "cf-crm-supabase-key": {
        "file": "PINAX.env",
        "extract": lambda: _read_env(_p("PINAX.env"), "SUPABASE_SERVICE_KEY")
                   or _read_env(_p("PINAX.env"), "VITE_SUPABASE_ANON_KEY")
                   or _read_env(_p("PINAX.env"), "SUPABASE_KEY")
                   or _read_env(_p("PINAX.env"), "CRM_SUPABASE_KEY"),
    },
    "pinax-crypto-key": {
        "file": "pinax/pinax_keys.txt",
        "extract": lambda: _read_env(_p("PINAX.env"), "PINAX_CRYPTO_KEY")
                   or _read_env(_p("PINAX.env"), "ENCRYPTION_KEY")
                   or _read_pinax_key(_p("pinax/pinax_keys.txt"), 0),
    },
    "pinax-supabase-jwt-secret": {
        "file": "pinax/pinax_keys.txt",
        "extract": lambda: _read_env(_p("PINAX.env"), "SUPABASE_JWT_SECRET")
                   or _read_env(_p("PINAX.env"), "JWT_SECRET")
                   or _read_pinax_key(_p("pinax/pinax_keys.txt"), 1),
    },
    "pinax-google-client-secrets": {
        "file": "pinax/client_secret_578790412002-orrrj3j314leidqve1emednrsdiknoum.apps.googleusercontent.com.json",
        "extract": lambda: _read_json_file(
            _p("pinax/client_secret_578790412002-orrrj3j314leidqve1emednrsdiknoum.apps.googleusercontent.com.json")),
    },
    "ga4-credentials": {
        "file": "client_secret_578790412002-ela0kqlpcdv5j5nnbrplknv0t52agnkc.apps.googleusercontent.com.json",
        "extract": lambda: _read_json_file(
            _p("client_secret_578790412002-ela0kqlpcdv5j5nnbrplknv0t52agnkc.apps.googleusercontent.com.json")),
    },
    "google-oauth-578790412002": {
        "file": "client_secret_578790412002-to650t95pva36mk6cfbi6fik2n0mihl0.apps.googleusercontent.com.json",
        "extract": lambda: _read_json_file(
            _p("client_secret_578790412002-to650t95pva36mk6cfbi6fik2n0mihl0.apps.googleusercontent.com.json")),
    },
    "bifrost-discord-token": {
        "file": "bifrost.env",
        "extract": lambda: _read_env(_p("bifrost.env"), "BIFROST_DISCORD_TOKEN")
                   or _read_env(_p("bifrost.env"), "DISCORD_TOKEN")
                   or _read_env(_p("bifrost.env"), "DISCORD_BOT_TOKEN"),
    },
    "bifrost-claude-api-key": {
        "file": "bifrost.env",
        "extract": lambda: _read_env(_p("bifrost.env"), "BIFROST_CLAUDE_API_KEY")
                   or _read_env(_p("bifrost.env"), "ANTHROPIC_API_KEY")
                   or _read_env(_p("bifrost.env"), "CLAUDE_API_KEY"),
    },
    "anthropic-api-key": {
        "file": "artforge.env",
        "extract": lambda: _read_env(_p("artforge.env"), "ANTHROPIC_API_KEY")
                   or _read_env(_p("MoleculeEQ_API.env"), "ANTHROPIC_API_KEY")
                   or _read_env(_p("ml_intern.env"), "ANTHROPIC_API_KEY"),
    },
    "huggingface-token": {
        "file": "HF_token.txt",
        "extract": lambda: _read_file(_p("HF_token.txt"))
                   or _read_env(_p("promptlabs.env"), "HF_TOKEN")
                   or _read_env(_p("promptlabs.env"), "HUGGINGFACE_TOKEN"),
        "note": "HF_token.txt may be empty (3 bytes) — check promptlabs.env fallback",
    },
    "promptlabs-openai": {
        "file": "promptlabs.env",
        "extract": lambda: _read_env(_p("promptlabs.env"), "OPENAI_API_KEY"),
    },
    "promptlabs-google": {
        "file": "promptlabs.env",
        "extract": lambda: _read_env(_p("promptlabs.env"), "GOOGLE_API_KEY")
                   or _read_env(_p("promptlabs.env"), "GOOGLE_AI_API_KEY")
                   or _read_env(_p("promptlabs.env"), "GEMINI_API_KEY"),
    },
    "promptlabs-aws-access-key": {
        "file": "promptlabs.env",
        "extract": lambda: _read_env(_p("promptlabs.env"), "AWS_ACCESS_KEY_ID"),
    },
    "promptlabs-aws-secret-key": {
        "file": "promptlabs.env",
        "extract": lambda: _read_env(_p("promptlabs.env"), "AWS_SECRET_ACCESS_KEY"),
    },
}


def _p(relative):
    """Resolve a path relative to the .secrets directory."""
    return os.path.join(SOURCE_DIR, relative)


def _extract_supabase_url(text):
    if not text:
        return None
    for line in text.split("\n"):
        if "supabase.co" in line.lower():
            match = re.search(r'https://\S+\.supabase\.co', line)
            if match:
                return match.group(0)
    return None


def _extract_supabase_key(text):
    if not text:
        return None
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("eyJ"):
            return stripped
        if "=" in stripped:
            _, _, v = stripped.partition("=")
            v = v.strip().strip('"').strip("'")
            if v.startswith("eyJ"):
                return v
    return None


def dry_run():
    """Show what would be populated without writing."""
    if not os.path.exists(SOURCE_DIR):
        print(f"Source directory not found: {SOURCE_DIR}")
        return False

    print("POPULATE DRY RUN")
    print("=" * 70)
    print(f"  Source: {SOURCE_DIR}")
    print(f"  Target: {SECRETS_JSON}")
    print()

    found = 0
    missing = 0
    for secret_name, info in sorted(SOURCE_MAP.items()):
        source_file = info["file"]
        source_path = _p(source_file)
        file_exists = os.path.exists(source_path)

        try:
            value = info["extract"]()
        except Exception as e:
            value = None

        if value and len(value) > 10:
            found += 1
            # Show type and length, never value
            is_json = value.strip().startswith("{")
            vtype = "JSON" if is_json else "string"
            print(f"  [FOUND] {secret_name:40s} {vtype:6s} {len(value):5d} chars  <- {source_file}")
        elif file_exists:
            missing += 1
            print(f"  [PARSE] {secret_name:40s} file exists but key not extracted  <- {source_file}")
        else:
            missing += 1
            print(f"  [MISS]  {secret_name:40s} source file not found  <- {source_file}")

    print(f"\n{'=' * 70}")
    print(f"  {found} found, {missing} missing/unparsed, {len(SOURCE_MAP)} total")
    return found > 0


def write_secrets():
    """Write extracted values to .secrets.json."""
    if not os.path.exists(SOURCE_DIR):
        print(f"Source directory not found: {SOURCE_DIR}")
        return False

    existing = {}
    if os.path.exists(SECRETS_JSON):
        with open(SECRETS_JSON, encoding="utf-8") as f:
            existing = json.load(f)

    updated = 0
    skipped = 0
    for secret_name, info in sorted(SOURCE_MAP.items()):
        try:
            value = info["extract"]()
        except Exception:
            value = None

        if value and len(value) > 10:
            existing[secret_name] = value
            updated += 1
        else:
            skipped += 1

    with open(SECRETS_JSON, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)

    print(f"Written: {updated} secrets updated, {skipped} skipped")
    print(f"Target: {SECRETS_JSON}")
    return updated > 0


def verify():
    """Verify .secrets.json has real values (not placeholders)."""
    if not os.path.exists(SECRETS_JSON):
        print("No .secrets.json found")
        return False

    with open(SECRETS_JSON, encoding="utf-8") as f:
        data = json.load(f)

    print("VERIFY .secrets.json")
    print("=" * 70)
    real = 0
    placeholder = 0
    for k, v in sorted(data.items()):
        if k.startswith("_"):
            continue
        if not isinstance(v, str):
            continue
        is_json = v.strip().startswith("{")
        is_real = len(v) > 20 and (
            is_json
            or v.startswith("sk_") or v.startswith("sk-")
            or v.startswith("am_") or v.startswith("hf_")
            or v.startswith("eyJ") or v.startswith("AKIA")
            or v.startswith("xoxb-") or v.startswith("gsk_")
            or v.startswith("https://")
            or len(v) > 30
        )
        if is_real:
            real += 1
            vtype = "JSON" if is_json else "str"
            print(f"  [OK]   {k:40s} {vtype:4s} {len(v):5d} chars")
        else:
            placeholder += 1
            print(f"  [???]  {k:40s} {len(v):5d} chars — may be placeholder")

    print(f"\n  {real} likely real, {placeholder} uncertain")
    return placeholder == 0


def main():
    parser = argparse.ArgumentParser(description="Populate keyring secrets from source files")
    parser.add_argument("--write", action="store_true", help="Write values to .secrets.json")
    parser.add_argument("--verify", action="store_true", help="Verify .secrets.json")
    args = parser.parse_args()

    if args.verify:
        verify()
    elif args.write:
        write_secrets()
    else:
        dry_run()


if __name__ == "__main__":
    main()
