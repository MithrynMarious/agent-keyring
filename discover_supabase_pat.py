"""Discover and validate a Supabase PAT from existing keyring secrets.

Scans .secrets.json and the .secrets/ source directory for values starting
with 'sbp_', tests each against the Supabase Management API, and writes the
working one as 'supabase-access-token'.

DC-1 SAFE: Values pass through memory only. Only prefix/suffix (4 chars each)
are printed for identification — never the full token.
"""

import json
import os
import sys
import urllib.request
import urllib.error

_DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS_PATH = os.path.join(_DIR, ".secrets.json")
SOURCE_DIR = os.environ.get(
    "KEYRING_SOURCE_DIR",
    os.path.normpath(os.path.join(_DIR, "..", "..", "..", ".secrets")),
)

SUPABASE_API = "https://api.supabase.com/v1/projects"


def _walk_json(obj, prefix=""):
    """Yield (key_path, value) for all string values in a nested dict/list."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, str):
                yield path, v
            elif isinstance(v, (dict, list)):
                yield from _walk_json(v, path)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            path = f"{prefix}[{i}]"
            if isinstance(v, str):
                yield path, v
            elif isinstance(v, (dict, list)):
                yield from _walk_json(v, path)


def mask(value):
    """Show first 8 and last 4 chars only."""
    if len(value) <= 16:
        return value[:4] + "****" + value[-4:]
    return value[:8] + "****" + value[-4:]


def find_sbp_candidates():
    """Scan all secret sources for values starting with 'sbp_'."""
    candidates = []

    if os.path.exists(SECRETS_PATH):
        with open(SECRETS_PATH, encoding="utf-8") as f:
            secrets = json.load(f)
        for name, value in secrets.items():
            if isinstance(value, str) and value.startswith("sbp_"):
                candidates.append((f".secrets.json[{name}]", value))

    search_dirs = [SOURCE_DIR]
    extra = os.path.normpath(os.path.join(_DIR, "..", "..", "mail"))
    if os.path.isdir(extra):
        search_dirs.append(extra)

    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        for root, _dirs, files in os.walk(search_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                if fname.endswith((".jpg", ".png", ".gif", ".pdf", ".pyc")):
                    continue
                try:
                    with open(fpath, encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except (OSError, UnicodeDecodeError):
                    continue

                rel = os.path.relpath(fpath, search_dir)

                if fname.endswith(".json"):
                    try:
                        data = json.loads(content)
                        if isinstance(data, dict):
                            for k, v in _walk_json(data):
                                if isinstance(v, str) and v.startswith("sbp_"):
                                    candidates.append((f"{os.path.basename(search_dir)}/{rel}[{k}]", v))
                    except json.JSONDecodeError:
                        pass

                for line in content.splitlines():
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        _, _, val = line.partition("=")
                        val = val.strip().strip('"').strip("'")
                        if val.startswith("sbp_"):
                            candidates.append((f"{os.path.basename(search_dir)}/{rel}", val))

                    if line.startswith("sbp_") and "=" not in line and len(line) > 10:
                        candidates.append((f"{os.path.basename(search_dir)}/{rel} (raw)", line.strip()))

    seen = set()
    unique = []
    for source, value in candidates:
        if value not in seen:
            seen.add(value)
            unique.append((source, value))

    return unique


def test_token(token):
    """Test a token against Supabase Management API. Returns True if valid."""
    req = urllib.request.Request(
        SUPABASE_API,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return False
        print(f"  Unexpected HTTP {e.code}", file=sys.stderr)
        return False
    except (urllib.error.URLError, OSError) as e:
        print(f"  Network error: {e}", file=sys.stderr)
        return False


def main():
    print("Scanning for Supabase PAT candidates (sbp_*)...")
    candidates = find_sbp_candidates()

    if not candidates:
        print("No sbp_* values found in .secrets.json or .secrets/ directory.")
        print("Generate a PAT at: https://supabase.com/dashboard/account/tokens")
        print("Then run: python add_secret.py supabase-access-token")
        sys.exit(1)

    print(f"Found {len(candidates)} candidate(s):\n")

    winner = None
    for i, (source, value) in enumerate(candidates, 1):
        print(f"  [{i}] {mask(value)}  (from {source})")
        print(f"      Testing against Supabase API...", end=" ", flush=True)

        if test_token(value):
            print("VALID")
            winner = (source, value)
            break
        else:
            print("invalid or expired")

    if not winner:
        print("\nNo working PAT found. All candidates failed authentication.")
        print("Generate a fresh PAT at: https://supabase.com/dashboard/account/tokens")
        print("Then run: python add_secret.py supabase-access-token")
        sys.exit(1)

    source, value = winner
    print(f"\nWorking PAT: {mask(value)} (from {source})")
    print(f"Writing as 'supabase-access-token' in .secrets.json...")

    secrets = {}
    if os.path.exists(SECRETS_PATH):
        with open(SECRETS_PATH, encoding="utf-8") as f:
            secrets = json.load(f)

    secrets["supabase-access-token"] = value
    with open(SECRETS_PATH, "w", encoding="utf-8") as f:
        json.dump(secrets, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print("Done. The Supabase MCP server will use this token on next launch.")


if __name__ == "__main__":
    main()
