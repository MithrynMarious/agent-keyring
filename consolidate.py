#!/usr/bin/env python3
"""consolidate.py — Credential discovery and consolidation for Agent Keyring.

Scans directory trees for scattered credentials (.env, JSON client secrets,
API key text files), classifies by service, detects duplicates and conflicts,
generates keyring .secrets.json and secret_manifest.json.

Security: values are held in memory for .secrets.json generation and hashed
for conflict detection. They are NEVER printed to stdout/stderr.

Usage:
    python consolidate.py scan <dir> [<dir>...]
    python consolidate.py migrate <dir> [<dir>...] -t <target>
    python consolidate.py generate <dir> [<dir>...] [-o <output_dir>]
    python consolidate.py audit <secrets_json> <dir> [<dir>...]
"""

import argparse
import hashlib
import json
import os
import shutil
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date


# ── Data ──

@dataclass
class FoundCredential:
    var_name: str
    keyring_name: str
    service: str
    source: str
    value_hash: str
    description: str
    _value: str = field(repr=False)


@dataclass
class KeySlot:
    keyring_name: str
    service: str
    description: str
    sources: list  # [(source_file, var_name, value_hash)]
    _value: str = field(repr=False, default="")

    @property
    def has_conflict(self):
        return len({h for _, _, h in self.sources}) > 1

    @property
    def is_duplicate(self):
        return len(self.sources) > 1 and not self.has_conflict


# ── Parsers ──

def parse_env(path):
    """Parse KEY=VALUE pairs from a .env file."""
    pairs = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key, val = key.strip(), val.strip()
                if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                    val = val[1:-1]
                if key and val and not val.startswith("#"):
                    pairs.append((key, val))
    except OSError:
        pass
    return pairs


def parse_json_credential(path):
    """Parse OAuth client secrets, Firebase SA keys, and similar JSON files."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []

    basename = os.path.basename(path).lower()
    blob = json.dumps(data, separators=(",", ":"))

    if basename.startswith("client_secret_") or "installed" in data or "web" in data:
        m = re.search(r"(\d{10,})-([a-z0-9]{6,12})", basename)
        if m:
            name = f"google-oauth-{m.group(1)}-{m.group(2)}"
        else:
            m2 = re.search(r"(\d{10,})", basename)
            name = f"google-oauth-{m2.group(1)}" if m2 else "google-oauth-unknown"
        return [(name, blob)]

    if "firebase" in basename or data.get("type") == "service_account":
        project = data.get("project_id", "unknown")
        return [(f"firebase-sa-{project}", blob)]

    if basename == "credentials.json":
        parent = os.path.basename(os.path.dirname(path)).lower()
        scope = parent if parent not in (".", "") else "default"
        return [(f"google-credentials-{scope}", blob)]

    if basename == "client_secrets.json":
        parent = os.path.basename(os.path.dirname(path)).lower()
        scope = parent if parent not in (".", "") else "default"
        return [(f"google-client-secrets-{scope}", blob)]

    return []


def parse_text_key(path):
    """Parse a plain-text file containing a single secret value."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            val = f.read().strip()
    except OSError:
        return []
    if not val or len(val) > 50000:
        return []
    stem = os.path.splitext(os.path.basename(path))[0]
    name = re.sub(r"[^a-zA-Z0-9]+", "-", stem).strip("-").lower()
    return [(name, val)]


# ── Classification ──

SERVICE_KEYWORDS = {
    "stripe": ("stripe",),
    "supabase": ("supabase",),
    "anthropic": ("anthropic", "claude-api"),
    "openai": ("openai",),
    "google-ai": ("google-api-key", "gemini-api"),
    "google-oauth": ("google-oauth", "client-secret-5", "client-secret-6",
                     "client-secret-8", "google-credentials"),
    "firebase": ("firebase",),
    "discord": ("discord",),
    "huggingface": ("hf-token", "huggingface"),
    "agentmail": ("agentmail",),
    "aws": ("aws-access", "aws-secret"),
    "azure": ("azure-api",),
    "teams": ("teams-app", "teams-tenant", "teams-api", "teamsapi"),
    "domo": ("domo",),
    "google-ads": ("google-ads",),
    "sftp": ("sftp",),
    "pinax": ("pinax",),
    "cohere": ("cohere",),
    "groq": ("groq",),
    "deepseek": ("deepseek",),
    "mistral": ("mistral",),
    "rdp": ("rdp-host", "rdp-gateway", "rdp-user"),
    "litify": ("litify",),
}


def classify(name):
    lower = name.lower().replace("_", "-")
    for svc, keywords in SERVICE_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return svc
    return "unknown"


def to_keyring_name(var_name, client_scope=None, source_scope=None):
    name = var_name.lower()
    had_framework_prefix = False
    for prefix in ("vite_", "next_public_", "react_app_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            had_framework_prefix = True
    name = re.sub(r"[^a-z0-9]+", "-", name).strip("-")
    if had_framework_prefix and source_scope:
        name = f"{source_scope}-{name}"
    if client_scope:
        name = f"client-{client_scope}-{name}"
    return name


def _source_scope(relpath):
    """Derive a scope prefix from the source filename for disambiguation."""
    stem = os.path.splitext(os.path.basename(relpath))[0].lower()
    stem = re.sub(r"[^a-z0-9]+", "-", stem).strip("-")
    for noise in ("env", "local", "production", "development"):
        stem = stem.replace(noise, "").strip("-")
    return stem if stem else None


def vhash(val):
    return hashlib.sha256(val.encode()).hexdigest()[:8]


# ── Scanner ──

SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", "venv", "env", ".venv",
    ".tox", "dist", "build", ".next", ".nuxt", ".cache", ".idea",
    ".vscode", "Thumbs.db",
})


def _is_env(name):
    lo = name.lower()
    return lo == ".env" or lo.startswith(".env.") or lo.endswith(".env")


def _is_json_cred(name):
    lo = name.lower()
    return (
        (lo.startswith("client_secret_") and lo.endswith(".json"))
        or ("firebase" in lo and "adminsdk" in lo and lo.endswith(".json"))
        or lo in ("credentials.json", "client_secrets.json")
        or lo.endswith("_credentials.json")
    )


def _is_text_key(name):
    lo = name.lower()
    if lo.endswith((".jpg", ".png", ".gif", ".jpeg", ".py", ".js", ".md")):
        return False
    if "dead" in lo or "expired" in lo or "old" in lo:
        return False
    if lo.endswith(".txt"):
        return any(kw in lo for kw in ("key", "token", "secret", "api", "credential"))
    if not os.path.splitext(lo)[1]:
        return any(kw in lo for kw in ("secret", "token", "key"))
    return False


def _detect_client_scope(relpath):
    """If path is under a clients/ directory, return the client slug."""
    parts = relpath.replace("\\", "/").lower().split("/")
    if "clients" in parts:
        idx = parts.index("clients")
        if idx + 1 < len(parts):
            stem = os.path.splitext(parts[idx + 1])[0]
            return re.sub(r"[^a-z0-9]+", "", stem)
    return None


def scan_directory(root, verbose=False):
    found = []
    root = os.path.normpath(root)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for name in filenames:
            filepath = os.path.join(dirpath, name)
            relpath = os.path.relpath(filepath, root)
            client_scope = _detect_client_scope(relpath)

            pairs = []
            if _is_env(name):
                pairs = parse_env(filepath)
                if verbose:
                    print(f"  env  {relpath} ({len(pairs)} vars)", file=sys.stderr)
            elif _is_json_cred(name):
                pairs = parse_json_credential(filepath)
                if verbose:
                    print(f"  json {relpath}", file=sys.stderr)
            elif _is_text_key(name):
                pairs = parse_text_key(filepath)
                if verbose:
                    print(f"  text {relpath}", file=sys.stderr)

            for var_name, value in pairs:
                scope = _source_scope(relpath) if not client_scope else None
                kname = to_keyring_name(var_name, client_scope, scope)
                svc = classify(kname)
                found.append(FoundCredential(
                    var_name=var_name,
                    keyring_name=kname,
                    service=svc,
                    source=relpath,
                    value_hash=vhash(value),
                    description=f"{var_name} ({svc})",
                    _value=value,
                ))

    return found


# ── Consolidation ──

def consolidate(creds):
    by_name = {}
    for c in creds:
        if c.keyring_name not in by_name:
            by_name[c.keyring_name] = KeySlot(
                keyring_name=c.keyring_name,
                service=c.service,
                description=c.description,
                sources=[],
                _value=c._value,
            )
        by_name[c.keyring_name].sources.append(
            (c.source, c.var_name, c.value_hash)
        )
    return sorted(by_name.values(), key=lambda s: (s.service, s.keyring_name))


# ── Reporting ──

def print_report(slots, roots):
    by_svc = defaultdict(list)
    for s in slots:
        by_svc[s.service].append(s)

    conflicts = [s for s in slots if s.has_conflict]
    dupes = [s for s in slots if s.is_duplicate]
    clients = [s for s in slots if s.keyring_name.startswith("client-")]
    core = [s for s in slots if not s.keyring_name.startswith("client-")]

    total_occ = sum(len(s.sources) for s in slots)
    total_files = len({src for s in slots for src, _, _ in s.sources})

    W = 60
    print(f"\n{'=' * W}")
    print(f" CREDENTIAL SCAN")
    print(f" Scanned: {', '.join(roots)}")
    print(f"{'=' * W}")
    print(f" {len(slots)} unique keys | {total_occ} occurrences | {total_files} files")
    print()

    for svc in sorted(by_svc.keys()):
        svc_slots = by_svc[svc]
        core_here = [s for s in svc_slots if not s.keyring_name.startswith("client-")]
        if not core_here:
            continue
        print(f"  {svc.upper()} ({len(core_here)})")
        for s in core_here:
            srcs = ", ".join(src for src, _, _ in s.sources)
            flag = "  ** CONFLICT" if s.has_conflict else ""
            print(f"    {s.keyring_name:<40} <- {srcs}{flag}")
        print()

    if clients:
        print(f"  CLIENT TIER ({len(clients)})")
        for s in sorted(clients, key=lambda s: s.keyring_name):
            srcs = ", ".join(src for src, _, _ in s.sources)
            print(f"    {s.keyring_name:<40} <- {srcs}")
        print()

    if conflicts:
        print(f"{'~' * W}")
        print(f" CONFLICTS — {len(conflicts)} keys with different values")
        print(f"{'~' * W}")
        for s in conflicts:
            print(f"\n  {s.keyring_name}:")
            by_hash = defaultdict(list)
            for src, var, h in s.sources:
                by_hash[h].append(src)
            for h, srcs in by_hash.items():
                print(f"    hash {h}: {', '.join(srcs)}")
        print(f"\n  Generator uses the first source found. Override by reordering scan dirs.")
        print()

    if dupes:
        dupe_summary = ", ".join(
            f"{s.keyring_name} ({len(s.sources)})" for s in dupes[:5]
        )
        print(f"  Duplicates: {len(dupes)} keys in multiple files, same value")
        print(f"    {dupe_summary}{'...' if len(dupes) > 5 else ''}")
        print()


# ── Generators ──

def gen_secrets(slots):
    return {s.keyring_name: s._value for s in slots}


def gen_manifest(slots):
    today = date.today().isoformat()
    entries = {}
    for s in slots:
        entries[s.keyring_name] = {
            "description": s.description,
            "service": s.service,
            "sources": [src for src, _, _ in s.sources],
            "added": today,
        }
    return {
        "_comment": "Secret names, descriptions, and service mappings. NO VALUES.",
        "secrets": entries,
    }


def gen_permissions_template(slots):
    """Generate a permissions.json template grouping keys by tier."""
    core_keys = [s.keyring_name for s in slots
                 if not s.keyring_name.startswith("client-")]
    client_keys = defaultdict(list)
    for s in slots:
        if s.keyring_name.startswith("client-"):
            parts = s.keyring_name.split("-", 2)
            slug = parts[1] if len(parts) > 2 else "default"
            client_keys[slug].append(s.keyring_name)

    perms = {
        "_comment": "Agent-to-secret ACL. Edit agent IDs and allowed lists.",
        "_admin": ["*"],
        "_default": [],
    }
    if client_keys:
        for slug, keys in sorted(client_keys.items()):
            perms[f"_client_{slug}"] = keys
    return perms


def gen_conflicts(slots):
    out = []
    for s in slots:
        if not s.has_conflict:
            continue
        by_hash = defaultdict(list)
        for src, var, h in s.sources:
            by_hash[h].append({"source": src, "var_name": var})
        out.append({
            "keyring_name": s.keyring_name,
            "service": s.service,
            "variants": [{"hash": h, "sources": srcs} for h, srcs in by_hash.items()],
        })
    return out


# ── Migration Helpers ──

def _env_dest_name(filepath):
    """Derive a descriptive .env filename from its directory context."""
    parent = os.path.basename(os.path.dirname(filepath)).lower()
    name = os.path.basename(filepath).lower()
    if name in (".env", ".env.local", ".env.production"):
        generic_dirs = {"web", "api", "app", "src", "server", "client", "frontend", "backend"}
        if parent in generic_dirs:
            grandparent = os.path.basename(
                os.path.dirname(os.path.dirname(filepath))
            ).lower()
            return f"{grandparent}-{parent}.env"
        return f"{parent}.env"
    return name if name.endswith(".env") else name


def _file_hash(path):
    """SHA-256 of file contents for dedup."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def _copy_credential(src, dest, dry_run=False, verbose=False):
    """Copy a credential file, returning (dest_path, status)."""
    if os.path.exists(dest):
        src_hash = _file_hash(src)
        dest_hash = _file_hash(dest)
        if src_hash == dest_hash:
            if verbose:
                print(f"  skip (identical): {os.path.basename(dest)}", file=sys.stderr)
            return dest, "identical"
        else:
            if verbose:
                print(f"  CONFLICT: {src} vs existing {dest}", file=sys.stderr)
            return dest, "conflict"

    if dry_run:
        if verbose:
            print(f"  would copy: {src} -> {dest}", file=sys.stderr)
        return dest, "would-copy"

    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy2(src, dest)
    if verbose:
        print(f"  copied: {src} -> {dest}", file=sys.stderr)
    return dest, "copied"


# ── Commands ──

def cmd_scan(args):
    creds = []
    for d in args.directories:
        d = os.path.expanduser(d)
        if not os.path.isdir(d):
            print(f"Skip (not a directory): {d}", file=sys.stderr)
            continue
        if args.verbose:
            print(f"Scanning {d}...", file=sys.stderr)
        creds.extend(scan_directory(d, verbose=args.verbose))

    if not creds:
        print("No credentials found.", file=sys.stderr)
        return 0

    slots = consolidate(creds)
    print_report(slots, args.directories)
    return 1 if any(s.has_conflict for s in slots) else 0


def cmd_generate(args):
    creds = []
    for d in args.directories:
        d = os.path.expanduser(d)
        if not os.path.isdir(d):
            print(f"Skip (not a directory): {d}", file=sys.stderr)
            continue
        if args.verbose:
            print(f"Scanning {d}...", file=sys.stderr)
        creds.extend(scan_directory(d, verbose=args.verbose))

    if not creds:
        print("No credentials found.", file=sys.stderr)
        return 1

    slots = consolidate(creds)
    print_report(slots, args.directories)

    out = args.output_dir or os.path.dirname(os.path.abspath(__file__))
    conflicts = [s for s in slots if s.has_conflict]

    if args.dry_run:
        print(f"DRY RUN — would write to {out}:")
        print(f"  .secrets.json        ({len(slots)} keys)")
        print(f"  secret_manifest.json ({len(slots)} entries)")
        if conflicts:
            print(f"  conflicts.json       ({len(conflicts)} conflicts)")
        print(f"  permissions.json     (template)")
        return 0

    sp = os.path.join(out, ".secrets.json")
    with open(sp, "w", encoding="utf-8") as f:
        json.dump(gen_secrets(slots), f, indent=2)
    print(f"Wrote {sp} ({len(slots)} keys)")

    mp = os.path.join(out, "secret_manifest.json")
    with open(mp, "w", encoding="utf-8") as f:
        json.dump(gen_manifest(slots), f, indent=2)
    print(f"Wrote {mp}")

    pp = os.path.join(out, "permissions_template.json")
    with open(pp, "w", encoding="utf-8") as f:
        json.dump(gen_permissions_template(slots), f, indent=2)
    print(f"Wrote {pp} (template — edit agent IDs before using)")

    if conflicts:
        cp = os.path.join(out, "conflicts.json")
        with open(cp, "w", encoding="utf-8") as f:
            json.dump(gen_conflicts(slots), f, indent=2)
        print(f"Wrote {cp} ({len(conflicts)} conflicts — resolve manually)")

    return 1 if conflicts else 0


def cmd_migrate(args):
    target = os.path.expanduser(args.target)
    os.makedirs(target, exist_ok=True)

    client_dirs = {}
    for spec in (args.client_dir or []):
        if "=" in spec:
            path, slug = spec.rsplit("=", 1)
        else:
            path = spec
            slug = re.sub(r"[^a-z0-9]+", "", os.path.basename(path).lower())
        client_dirs[os.path.normpath(os.path.expanduser(path))] = slug

    copied, skipped, conflicts = [], [], []
    seen_hashes = {}
    planned_dests = {}  # dest_path -> (src_path, file_hash) for dry-run collision detection

    for d in args.directories:
        d = os.path.expanduser(d)
        if not os.path.isdir(d):
            print(f"Skip (not a directory): {d}", file=sys.stderr)
            continue

        for dirpath, dirnames, filenames in os.walk(d):
            dirnames[:] = [dn for dn in dirnames if dn not in SKIP_DIRS]

            for name in filenames:
                filepath = os.path.join(dirpath, name)

                if not (_is_env(name) or _is_json_cred(name) or _is_text_key(name)):
                    continue

                is_client = False
                client_slug = None
                norm_dir = os.path.normpath(dirpath)
                for cdir, cslug in client_dirs.items():
                    if norm_dir.startswith(cdir):
                        is_client = True
                        client_slug = cslug
                        break
                if not is_client:
                    client_slug = _detect_client_scope(
                        os.path.relpath(filepath, d)
                    )
                    is_client = client_slug is not None

                if is_client:
                    dest_dir = os.path.join(target, "clients")
                else:
                    dest_dir = target

                if _is_env(name):
                    dest_name = _env_dest_name(filepath)
                else:
                    dest_name = name

                dest = os.path.join(dest_dir, dest_name)

                try:
                    fhash = _file_hash(filepath)
                except OSError:
                    continue

                if fhash in seen_hashes:
                    if args.verbose:
                        print(f"  dedup: {filepath} == {seen_hashes[fhash]}",
                              file=sys.stderr)
                    skipped.append((filepath, "duplicate"))
                    continue
                seen_hashes[fhash] = filepath

                if dest in planned_dests:
                    prev_src, prev_hash = planned_dests[dest]
                    if fhash == prev_hash:
                        skipped.append((filepath, "identical"))
                        if args.verbose:
                            print(f"  skip (same as planned): {filepath}",
                                  file=sys.stderr)
                        continue
                    else:
                        conflicts.append((filepath, dest))
                        if args.verbose:
                            print(f"  CONFLICT (dest collision): {filepath} vs {prev_src}",
                                  file=sys.stderr)
                        continue

                _, status = _copy_credential(
                    filepath, dest,
                    dry_run=args.dry_run, verbose=args.verbose,
                )
                if status == "copied" or status == "would-copy":
                    copied.append((filepath, dest))
                    planned_dests[dest] = (filepath, fhash)
                elif status == "identical":
                    skipped.append((filepath, "identical"))
                    planned_dests[dest] = (filepath, fhash)
                elif status == "conflict":
                    conflicts.append((filepath, dest))

    W = 60
    print(f"\n{'=' * W}")
    print(f" MIGRATE {'(DRY RUN) ' if args.dry_run else ''}-> {target}")
    print(f"{'=' * W}")
    print(f"  Copied:    {len(copied)}")
    print(f"  Skipped:   {len(skipped)} (identical or duplicate)")
    print(f"  Conflicts: {len(conflicts)}")

    if copied and args.verbose:
        print(f"\n  Files {'to copy' if args.dry_run else 'copied'}:")
        for src, dst in copied:
            print(f"    {src}")
            print(f"      -> {dst}")

    if conflicts:
        print(f"\n  CONFLICTS (target already has different file):")
        for src, dst in conflicts:
            print(f"    {src}")
            print(f"      vs {dst}")
        print(f"  Resolve manually, then re-run.")

    if not args.dry_run and copied and not conflicts:
        print(f"\n  Running generate on {target}...")
        gen_args = argparse.Namespace(
            directories=[target],
            output_dir=args.output_dir,
            verbose=args.verbose,
            dry_run=False,
        )
        cmd_generate(gen_args)

    print()
    return 1 if conflicts else 0


def cmd_sync_skeleton(args):
    """Sync the skeleton keyring from .secrets.json — keys only, no values."""
    secrets_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".secrets.json")
    skeleton_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 ".secrets.skeleton.json")
    manifest_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "secret_manifest.json")

    if not os.path.exists(secrets_path):
        print("No .secrets.json found. Nothing to sync.", file=sys.stderr)
        return 1

    with open(secrets_path, encoding="utf-8") as f:
        secrets = json.load(f)

    manifest = {}
    if os.path.exists(manifest_path):
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f).get("secrets", {})

    skeleton = {
        "_comment": "SKELETON — shape only, NO values. Agents read THIS file "
                    "to understand keyring structure. NEVER read .secrets.json "
                    "directly (DC-1).",
        "_instructions": "To add a new secret: (1) Place the value file in "
                         "C:\\CrystallineCity\\.secrets\\, (2) Run: python "
                         "tools/keyring/consolidate.py sync-skeleton, (3) Add "
                         "the entry to secret_manifest.json with description "
                         "and service.",
    }

    for key in secrets:
        if key.startswith("_"):
            continue
        desc = manifest.get(key, {}).get("description", key)
        svc = manifest.get(key, {}).get("service", classify(key))
        skeleton[key] = f"<{svc}:{key}>"

    with open(skeleton_path, "w", encoding="utf-8") as f:
        json.dump(skeleton, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Skeleton synced: {len(skeleton) - 2} keys (no values)")
    print(f"  Wrote: {skeleton_path}")
    return 0


def cmd_ingest_secrets_dir(args):
    """Scan .secrets/ directory for new files and register them in keyring."""
    secrets_dir = args.secrets_dir or os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", "..", "..", ".secrets"))
    if not os.path.isdir(secrets_dir):
        print(f"Secrets directory not found: {secrets_dir}", file=sys.stderr)
        return 1

    secrets_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".secrets.json")
    manifest_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "secret_manifest.json")

    existing_secrets = {}
    if os.path.exists(secrets_path):
        with open(secrets_path, encoding="utf-8") as f:
            existing_secrets = json.load(f)

    existing_manifest = {"_comment": "Secret names, descriptions, and service "
                         "mappings. NO VALUES here — values live in the secret "
                         "store.", "secrets": {}}
    if os.path.exists(manifest_path):
        with open(manifest_path, encoding="utf-8") as f:
            existing_manifest = json.load(f)

    INGEST_EXTENSIONS = {".txt", ".env", ".json"}
    SKIP_EXTENSIONS = {".py", ".jpg", ".jpeg", ".png", ".gif", ".bat", ".ps1",
                       ".sh", ".md", ".log", ".csv"}

    added = []
    for name in os.listdir(secrets_dir):
        filepath = os.path.join(secrets_dir, name)
        if not os.path.isfile(filepath):
            continue
        if name.startswith("."):
            continue
        ext = os.path.splitext(name)[1].lower()
        if ext in SKIP_EXTENSIONS:
            continue
        if ext and ext not in INGEST_EXTENSIONS:
            continue

        stem = os.path.splitext(name)[0]
        key = re.sub(r"[^a-zA-Z0-9]+", "-", stem).strip("-").lower()

        if key in existing_secrets and not str(existing_secrets[key]).startswith("PASTE_FROM"):
            continue

        existing_secrets[key] = f"PASTE_FROM: .secrets/{name}"

        if key not in existing_manifest.get("secrets", {}):
            svc = classify(key)
            existing_manifest.setdefault("secrets", {})[key] = {
                "description": f"{stem} ({svc})",
                "service": svc,
                "sources": [os.path.join(secrets_dir, name)],
                "added": date.today().isoformat(),
            }

        added.append((key, name))

    if not added:
        print("No new secrets found in", secrets_dir)
        return 0

    if not args.dry_run:
        with open(secrets_path, "w", encoding="utf-8") as f:
            json.dump(existing_secrets, f, indent=2, ensure_ascii=False)
            f.write("\n")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(existing_manifest, f, indent=2, ensure_ascii=False)
            f.write("\n")

    print(f"{'Would add' if args.dry_run else 'Added'} {len(added)} secret(s):")
    for key, filename in added:
        print(f"  {key:<45} <- {filename}")

    if not args.dry_run:
        sync_args = argparse.Namespace()
        cmd_sync_skeleton(sync_args)

    return 0


def cmd_audit(args):
    sp = args.secrets_json
    if not os.path.exists(sp):
        print(f"Not found: {sp}", file=sys.stderr)
        return 1

    with open(sp, encoding="utf-8") as f:
        existing = json.load(f)

    creds = []
    for d in args.directories:
        d = os.path.expanduser(d)
        if os.path.isdir(d):
            creds.extend(scan_directory(d, verbose=args.verbose))

    slots = consolidate(creds)
    found = {s.keyring_name for s in slots}
    have = {k for k in existing if not k.startswith("_")}

    missing_from_keyring = found - have
    orphaned = have - found

    print(f"\n AUDIT — {sp}")
    print(f"{'=' * 50}")
    print(f" Keyring: {len(have)} keys")
    print(f" On disk: {len(found)} keys")

    if missing_from_keyring:
        print(f"\n NOT IN KEYRING ({len(missing_from_keyring)}):")
        for n in sorted(missing_from_keyring):
            s = next(x for x in slots if x.keyring_name == n)
            print(f"   {n:<40} <- {s.sources[0][0]}")

    if orphaned:
        print(f"\n IN KEYRING BUT NOT ON DISK ({len(orphaned)}):")
        for n in sorted(orphaned):
            val = existing[n]
            placeholder = "PASTE_FROM" in str(val) if isinstance(val, str) else False
            tag = " (placeholder)" if placeholder else ""
            print(f"   {n}{tag}")

    if not missing_from_keyring and not orphaned:
        print(f"\n All keys accounted for. Keyring is in sync with disk.")

    # Staleness check: compare hashes
    stale = 0
    for s in slots:
        if s.keyring_name in have:
            disk_hash = s.value_hash
            keyring_hash = vhash(str(existing.get(s.keyring_name, "")))
            if disk_hash != keyring_hash:
                if stale == 0:
                    print(f"\n STALE (keyring value differs from disk):")
                stale += 1
                print(f"   {s.keyring_name:<40} keyring:{keyring_hash} disk:{disk_hash}")

    print()
    return 1 if missing_from_keyring else 0


# ── Main ──

def main():
    p = argparse.ArgumentParser(
        description="Credential consolidation for Agent Keyring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s scan ~/projects ~/.secrets
  %(prog)s generate ~/.secrets -o ./keyring/
  %(prog)s generate ~/.secrets ~/projects --dry-run
  %(prog)s audit ./keyring/.secrets.json ~/.secrets
""",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Discover and classify credentials")
    s.add_argument("directories", nargs="+")

    g = sub.add_parser("generate", help="Generate .secrets.json + manifest")
    g.add_argument("directories", nargs="+")
    g.add_argument("-o", "--output-dir")
    g.add_argument("--dry-run", action="store_true")

    m = sub.add_parser("migrate", help="Copy credentials into .secrets/ and generate keyring")
    m.add_argument("directories", nargs="+", help="Source directories to scan")
    m.add_argument("-t", "--target", required=True, help="Target .secrets/ directory")
    m.add_argument("-o", "--output-dir", help="Keyring output dir (default: beside this script)")
    m.add_argument("--client-dir", action="append",
                   help="Path[=slug] to treat as client-scoped (repeatable)")
    m.add_argument("--dry-run", action="store_true")

    a = sub.add_parser("audit", help="Audit keyring against disk")
    a.add_argument("secrets_json")
    a.add_argument("directories", nargs="+")

    sk = sub.add_parser("sync-skeleton",
                        help="Rebuild .secrets.skeleton.json from .secrets.json (keys only)")

    ing = sub.add_parser("ingest",
                         help="Scan .secrets/ dir for new files and register in keyring")
    ing.add_argument("--secrets-dir",
                     help="Path to .secrets/ directory (default: ../../../.secrets)")
    ing.add_argument("--dry-run", action="store_true")

    args = p.parse_args()
    handlers = {"scan": cmd_scan, "generate": cmd_generate,
                "migrate": cmd_migrate, "audit": cmd_audit,
                "sync-skeleton": cmd_sync_skeleton,
                "ingest": cmd_ingest_secrets_dir}
    sys.exit(handlers[args.command](args))


if __name__ == "__main__":
    main()
