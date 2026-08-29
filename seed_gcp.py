"""Seed GCP Secret Manager from the local keyring store.

Reads .secrets.json, resolves PASTE_FROM references to actual file content,
and uploads each secret to GCP Secret Manager via gcloud CLI.

Usage:
    python seed_gcp.py PROJECT_ID [--prefix keyring-] [--dry-run]

DC-1: This script handles secret values during migration. It reads them from
disk and pipes them to gcloud via stdin — values never appear in command-line
arguments, logs, or output.
"""

import json
import os
import platform
import subprocess
import sys

# gcloud on Windows is a .cmd wrapper; subprocess needs shell=True
_SHELL = platform.system() == "Windows"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS_FILE = os.path.join(SCRIPT_DIR, ".secrets.json")
# PASTE_FROM paths resolve against KEYRING_SECRETS_ROOT env var, or 3 dirs up
SECRETS_ROOT = os.environ.get("KEYRING_SECRETS_ROOT") or os.path.normpath(
    os.path.join(SCRIPT_DIR, "..", "..", ".."))
SKIP_KEYS = {"_comment", "_instructions"}


def resolve_value(raw: str) -> str | None:
    """Resolve a secret value, following PASTE_FROM references."""
    if not isinstance(raw, str):
        return json.dumps(raw) if raw is not None else None

    if raw.startswith("PASTE_FROM:"):
        ref_path = raw.split(":", 1)[1].strip()
        if os.path.isabs(ref_path):
            full_path = ref_path
        else:
            full_path = os.path.normpath(os.path.join(SECRETS_ROOT, ref_path))

        if not os.path.exists(full_path):
            return None
        with open(full_path, encoding="utf-8", errors="replace") as f:
            return f.read().strip()

    return raw


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: python seed_gcp.py PROJECT_ID [--prefix keyring-] [--dry-run]")
        sys.exit(1)

    project = sys.argv[1]
    prefix = "keyring-"
    dry_run = "--dry-run" in sys.argv

    for i, arg in enumerate(sys.argv):
        if arg == "--prefix" and i + 1 < len(sys.argv):
            prefix = sys.argv[i + 1]

    if not os.path.exists(SECRETS_FILE):
        print(f"Error: {SECRETS_FILE} not found")
        sys.exit(1)

    with open(SECRETS_FILE, encoding="utf-8") as f:
        secrets = json.load(f)

    created = 0
    updated = 0
    skipped = 0
    failed = 0

    for name, raw_value in secrets.items():
        if name in SKIP_KEYS:
            continue

        value = resolve_value(raw_value)
        if value is None:
            print(f"  SKIP  {name} (PASTE_FROM file not found)")
            skipped += 1
            continue

        if not value.strip():
            print(f"  SKIP  {name} (empty value)")
            skipped += 1
            continue

        gcp_name = f"{prefix}{name}"

        if dry_run:
            source = "PASTE_FROM" if str(raw_value).startswith("PASTE_FROM:") else "inline"
            print(f"  WOULD CREATE  {gcp_name} ({source}, {len(value)} bytes)")
            created += 1
            continue

        # Create secret — value piped via stdin (DC-1: never in CLI args)
        proc = subprocess.run(
            ["gcloud", "secrets", "create", gcp_name,
             "--data-file=-", f"--project={project}"],
            input=value.encode("utf-8"),
            capture_output=True,
            shell=_SHELL
        )

        if proc.returncode == 0:
            print(f"  CREATE  {gcp_name}")
            created += 1
        else:
            err = proc.stderr.decode()
            if "ALREADY_EXISTS" in err:
                proc2 = subprocess.run(
                    ["gcloud", "secrets", "versions", "add", gcp_name,
                     "--data-file=-", f"--project={project}"],
                    input=value.encode("utf-8"),
                    capture_output=True,
                    shell=_SHELL
                )
                if proc2.returncode == 0:
                    print(f"  UPDATE  {gcp_name}")
                    updated += 1
                else:
                    print(f"  FAIL    {gcp_name}: {proc2.stderr.decode().strip()}")
                    failed += 1
            else:
                print(f"  FAIL    {gcp_name}: {err.strip()}")
                failed += 1

    action = "Would seed" if dry_run else "Seeded"
    print(f"\n{action} GCP Secret Manager ({project}):")
    print(f"  Created: {created}")
    if updated:
        print(f"  Updated: {updated}")
    if skipped:
        print(f"  Skipped: {skipped}")
    if failed:
        print(f"  Failed:  {failed}")


if __name__ == "__main__":
    main()
