"""Launch the Supabase MCP server with credentials from the keyring store.

The agent never sees the raw token — this script reads it from .secrets.json
and injects it as SUPABASE_ACCESS_TOKEN into the subprocess environment.
DC-1 compliant: keys on the key ring, not in your mouth.
"""

import json
import os
import subprocess
import sys

KEYRING_DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS_PATH = os.path.join(KEYRING_DIR, ".secrets.json")


def main():
    if not os.path.exists(SECRETS_PATH):
        print(f"Secret store not found: {SECRETS_PATH}", file=sys.stderr)
        sys.exit(1)

    with open(SECRETS_PATH, encoding="utf-8") as f:
        secrets = json.load(f)

    token = secrets.get("supabase-access-token")
    if not token:
        print("supabase-access-token not found in keyring secret store", file=sys.stderr)
        print("Add it to .secrets.json: the Supabase personal access token (PAT)", file=sys.stderr)
        print("Generate one at: https://supabase.com/dashboard/account/tokens", file=sys.stderr)
        sys.exit(1)

    env = os.environ.copy()
    env["SUPABASE_ACCESS_TOKEN"] = token

    subprocess.run(
        ["npx", "-y", "@supabase/mcp-server-supabase@latest"],
        env=env,
        stdin=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )


if __name__ == "__main__":
    main()
