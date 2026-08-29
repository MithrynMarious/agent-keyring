"""Add or update a single secret in the keyring's .secrets.json store.

DC-1 SAFE: The value is read from stdin (not command-line args, which appear
in process lists). It passes through memory only during the write — never
printed, logged, or sent anywhere.

Usage:
  echo "your-token-value" | python add_secret.py supabase-access-token
  python add_secret.py supabase-access-token  # prompts interactively

Options:
  --verify    After writing, confirm the key exists (prints name only, not value)
  --list      Show all key names currently in the store (no values)
"""

import json
import os
import sys

_DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS_PATH = os.path.join(_DIR, ".secrets.json")
MANIFEST_PATH = os.path.join(_DIR, "secret_manifest.json")


def load_secrets():
    if not os.path.exists(SECRETS_PATH):
        return {}
    with open(SECRETS_PATH, encoding="utf-8") as f:
        return json.load(f)


def save_secrets(secrets):
    with open(SECRETS_PATH, "w", encoding="utf-8") as f:
        json.dump(secrets, f, indent=2, ensure_ascii=False)
        f.write("\n")


def load_manifest():
    if not os.path.exists(MANIFEST_PATH):
        return {}
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        return json.load(f)


def main():
    if "--list" in sys.argv:
        secrets = load_secrets()
        if not secrets:
            print("Secret store is empty or missing.")
        else:
            print(f"{len(secrets)} secret(s) in store:")
            for name in sorted(secrets.keys()):
                print(f"  {name}")
        return

    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print("Usage: python add_secret.py <secret-name> [--verify]")
        print("       python add_secret.py --list")
        print()
        manifest = load_manifest()
        if manifest.get("secrets"):
            print("Registered secret names (from manifest):")
            for name, info in sorted(manifest["secrets"].items()):
                print(f"  {name} — {info.get('description', '')}")
        return

    secret_name = args[0]
    verify = "--verify" in sys.argv

    manifest = load_manifest()
    if manifest.get("secrets") and secret_name not in manifest["secrets"]:
        print(f"Warning: '{secret_name}' is not in secret_manifest.json", file=sys.stderr)
        print("It will be added to .secrets.json but won't be visible to keyring tools", file=sys.stderr)
        print("until you also register it in secret_manifest.json.", file=sys.stderr)

    if sys.stdin.isatty():
        print(f"Enter value for '{secret_name}' (input is hidden):")
        try:
            import getpass
            value = getpass.getpass(prompt="  Value: ")
        except (ImportError, EOFError):
            value = input("  Value: ")
    else:
        value = sys.stdin.read().strip()

    if not value:
        print("Error: empty value. Aborting.", file=sys.stderr)
        sys.exit(1)

    secrets = load_secrets()
    existed = secret_name in secrets
    secrets[secret_name] = value
    save_secrets(secrets)

    action = "Updated" if existed else "Added"
    print(f"{action} '{secret_name}' in {SECRETS_PATH}")
    print(f"Store now has {len(secrets)} secret(s).")

    if verify:
        reloaded = load_secrets()
        if secret_name in reloaded:
            print(f"Verified: '{secret_name}' exists in store.")
        else:
            print(f"ERROR: '{secret_name}' not found after write!", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
