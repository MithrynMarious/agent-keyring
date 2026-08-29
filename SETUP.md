# Agent Keyring — Setup Guide

How to get the keyring running on a new machine. Two backends:
local file (quick, single-machine) or GCP Secret Manager (shared across machines).

**Pick your path, then work the checklist.** Each step has a checkbox — check it off
when done so you can resume if interrupted. Steps marked with `📎 Memory` have
reference notes from prior setups — read them if you get stuck.

---

## Prerequisites

- [ ] Python 3.12+ installed
- [ ] Repo cloned (or standalone `agent-keyring` repo)
- [ ] `pip install mcp[cli]` (the only hard dependency)

---

## Option A: Local File Store (Single Machine)

Fast setup. Secrets live in `.secrets.json` on disk. Each machine has its own copy.

### A-1: Create the secrets file

- [ ] Create `.secrets.json` in the keyring directory

```bash
cp .secrets.skeleton.json .secrets.json
# Edit .secrets.json — replace placeholders with real values
```

Format: flat JSON, key names match `secret_manifest.json`:

```json
{
  "agentmail-api-key": "am_live_...",
  "stripe-secret-key": "sk_live_..."
}
```

The file is gitignored. Never commit it.

### A-2: Populate secrets

- [ ] Add at least one secret to `.secrets.json`

**Add a single secret:**

```bash
python add_secret.py supabase-access-token          # prompts for value interactively
echo "sbp_your_token" | python add_secret.py supabase-access-token  # piped (scripting)
python add_secret.py supabase-access-token --verify  # add + confirm it wrote
python add_secret.py --list                          # show all key names (no values)
python add_secret.py                                 # show all registered names from manifest
```

The value is read from stdin, never from command-line args (which appear in process
lists). DC-1 safe.

**From scratch (bulk):** Open `.secrets.json` and paste each value. Key names must match
the entries in `secret_manifest.json`.

**From an existing machine:** Use the consolidator to scan, migrate, and generate:

```bash
python consolidate.py scan C:\path\to\projects
python consolidate.py migrate C:\path\to\projects --target .secrets/
python consolidate.py generate .secrets/ --output .secrets.json
python consolidate.py audit .secrets.json
```

**Manual secure transfer:** Copy `.secrets.json` via USB drive, encrypted archive,
or a secure channel. Never email, Slack, or commit it.

> 📎 **Memory — A-2 (E-1185):** First ingest run picked up `.jpg` and `.py` files
> alongside actual secrets. The extension whitelist (`.txt`, `.env`, `.json`) was
> added to prevent non-secret files from polluting the keyring. If you have
> credential files in unusual formats, rename them to `.txt` before ingest.

### A-3: Register the MCP server

- [ ] Add keyring to `.mcp.json`

```json
{
  "mcpServers": {
    "keyring": {
      "command": "python",
      "args": ["tools/keyring/server.py"],
      "cwd": "<repo-root>/tools/keyring"
    }
  }
}
```

### A-4: Verify local store works

- [ ] Run the verification command and confirm secrets load

```bash
python -c "from secret_store import LocalFileStore; s = LocalFileStore('.secrets.json'); print(f'{len(s.list_names())} secrets loaded')"
```

**Expected:** A number > 0 followed by "secrets loaded". If 0, check that `.secrets.json`
exists and has entries.

> 📎 **Memory — A-4 (E-1185):** If you used `PASTE_FROM:` references during ingest
> and get 0 secrets, the likely cause is path resolution. `PASTE_FROM:` paths
> resolve against `KEYRING_SECRETS_ROOT` (env var) or 3 directories up from the
> keyring. Set `KEYRING_SECRETS_ROOT` to the parent of your `.secrets/` directory
> if the default doesn't match your layout.

**You're done with Option A.** Skip to [Health Monitoring](#health-monitoring) or
[Keyring-Backed MCP Servers](#keyring-backed-mcp-servers) for optional next steps.

---

## Option B: GCP Secret Manager (Multi-Machine)

Both machines read from the same GCP project. No `.secrets.json` on disk after migration.
Secrets are created once in GCP and accessible from any authenticated machine.

### B-1: Enable GCP APIs

- [ ] Enable Secret Manager API
- [ ] Enable Analytics APIs (if needed for GA4 adapter)

```bash
gcloud services enable secretmanager.googleapis.com --project=YOUR_PROJECT_ID
```

If you also need Analytics APIs:

```bash
gcloud services enable analyticsdata.googleapis.com --project=YOUR_PROJECT_ID
gcloud services enable analyticsadmin.googleapis.com --project=YOUR_PROJECT_ID
gcloud services enable tagmanager.googleapis.com --project=YOUR_PROJECT_ID
```

> 📎 **Memory — B-1 (F-001):** Searching "Analytics Data" in the GCP console buries
> the exact match below similarly-named APIs. Three appear: Google Analytics Admin,
> Google Analytics, and Analytics Data API. The one the keyring's GA4 adapter calls
> is **Analytics Data API** (`analyticsdata.googleapis.com`) — it was third in the
> list despite being the exact search term. If you're enabling via the console
> instead of `gcloud`, scroll past the first two results.

### B-2: Create a service account

- [ ] Create service account in IAM & Admin
- [ ] Grant Secret Manager Secret Accessor role
- [ ] Download JSON key
- [ ] Rename key file for traceability
- [ ] Place key in `.secrets/` directory

Go to **IAM & Admin > Service Accounts > Create Service Account** (top-level nav, not
inside a specific API page).

- Name: `keyring-agent` (or similar)
- Description: "Keyring secret accessor for agent workstations"
- Grant role: **Secret Manager Secret Accessor** (`roles/secretmanager.secretAccessor`)

After creation, go to the service account's **Keys tab > Add Key > Create new key > JSON**.
Download the key file, rename it to include "keyring" for traceability, and place it in
your `.secrets/` directory. Run `python consolidate.py ingest` to register it.

> 📎 **Memory — B-2 (F-002 through F-005):** Four friction points hit during first
> setup, all in the GCP console:
>
> 1. **IAP appears alongside service accounts (F-002).** IAP (Identity-Aware Proxy)
>    protects web apps with Google sign-in — completely different purpose, but
>    "access control" is in the same navigation neighborhood. Ignore it. You want
>    **IAM & Admin > Service Accounts**, not IAP.
>
> 2. **SA creation dumps you at the list, not the detail page (F-003).** After
>    clicking Create, you land on the service account list. Your new SA is at
>    the **bottom, below the fold**. You'll need to scroll down. It's not that
>    creation failed — the redirect just doesn't take you where you expect.
>
> 3. **The "Grant access" step looks optional but isn't (F-004).** The multi-step
>    wizard includes a "Grant this service account access to project" panel that
>    presents like an optional extra. If you skip it, the SA has **zero roles** and
>    every Secret Manager call will return "permission denied" with no connection
>    to this skipped step. If you already skipped it: **IAM & Admin > IAM > Grant
>    Access** and add the role after the fact.
>
> 4. **Key download uses opaque naming (F-005).** The JSON key downloads as
>    `project-id-hexhash.json` (e.g., `coreforged-city-ec36841bd162.json`). In a
>    directory with 30+ credential files, it's indistinguishable from other JSON
>    keys without opening it. Rename it to include "keyring" or the SA name
>    immediately after download.
>
> Full friction details: `FRICTION_JOURNAL.md` in this repo.

### B-3: Upload secrets to GCP

- [ ] Upload at least one secret to GCP Secret Manager

Each secret is stored with the prefix `keyring-` (configurable). Create them:

```bash
# One-liner per secret
echo -n "am_live_abc123" | gcloud secrets create keyring-agentmail-api-key \
  --data-file=- --project=YOUR_PROJECT_ID

echo -n "sk_live_xyz789" | gcloud secrets create keyring-stripe-secret-key \
  --data-file=- --project=YOUR_PROJECT_ID
```

For JSON-valued secrets (service account keys, OAuth credentials):

```bash
gcloud secrets create keyring-firebase-sa-key \
  --data-file=path/to/service-account.json --project=YOUR_PROJECT_ID
```

To update an existing secret's value:

```bash
echo -n "new_value" | gcloud secrets versions add keyring-agentmail-api-key \
  --data-file=- --project=YOUR_PROJECT_ID
```

**Bulk migration from local store:** If you have a populated `.secrets.json`, use the
seed script instead of uploading one by one:

```bash
python seed_gcp.py YOUR_PROJECT_ID --dry-run    # preview
python seed_gcp.py YOUR_PROJECT_ID              # upload all
```

> 📎 **Memory — B-3 (S-02 seeding session):** Three gotchas from seeding 45 secrets
> into GCP:
>
> 1. **`PASTE_FROM:` references must resolve first.** If your `.secrets.json` uses
>    `PASTE_FROM: .secrets/filename` references (from `consolidate.py ingest`),
>    `seed_gcp.py` follows them automatically. But the paths resolve against
>    `KEYRING_SECRETS_ROOT` or 3 directories up from the script. If you see
>    "SKIP (PASTE_FROM file not found)" in the dry-run, set `KEYRING_SECRETS_ROOT`
>    to the parent of your `.secrets/` directory.
>
> 2. **Windows: `gcloud` is a `.cmd` wrapper.** `subprocess.run(["gcloud", ...])`
>    fails with `FileNotFoundError` on Windows because `gcloud.cmd` isn't a direct
>    executable. `seed_gcp.py` handles this with `shell=True` on Windows. If you
>    write your own upload scripts, add `shell=True` on Windows or call `gcloud.cmd`
>    directly.
>
> 3. **ALREADY_EXISTS is not an error.** If a secret already exists, `seed_gcp.py`
>    adds a new version instead of failing. Running the script twice is safe — it
>    won't duplicate, it will version.

### B-4: Authenticate the machine

- [ ] Set up GCP authentication (pick one sub-option)

**Option B-4a: Application Default Credentials (developer machines)**

```bash
gcloud auth application-default login
```

This creates `~/.config/gcloud/application_default_credentials.json` (Linux/Mac)
or `%APPDATA%\gcloud\application_default_credentials.json` (Windows). The keyring
finds it automatically.

**Option B-4b: Service account key (CI/headless)**

Download a service account key JSON with `Secret Manager Secret Accessor` role:

```bash
gcloud iam service-accounts keys create sa-key.json \
  --iam-account=keyring@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

Grant the role:

```bash
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:keyring@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

Set the environment variable:

```bash
export KEYRING_GCP_SA_KEY=/path/to/sa-key.json     # Linux/Mac
$env:KEYRING_GCP_SA_KEY = "C:\path\to\sa-key.json" # Windows PowerShell
```

**Option B-4c: GCE/Cloud Run (automatic)**

On Compute Engine or Cloud Run, the keyring uses the metadata server automatically.
Attach the `Secret Manager Secret Accessor` role to the instance's service account.

> 📎 **Memory — B-4 (E-1166):** The GCP store tries three auth paths in order:
> (1) service account key file via `KEYRING_GCP_SA_KEY` or
> `GOOGLE_APPLICATION_CREDENTIALS`, (2) gcloud ADC token file, (3) GCE metadata
> server. If "No GCP credentials found" fires, none of the three paths resolved.
> Most common cause on developer machines: `gcloud auth application-default login`
> was never run, or ran in a different terminal/user profile. The ADC file lands in
> `%APPDATA%\gcloud\` on Windows — check that the file actually exists there.

### B-5: Configure environment

- [ ] Set `KEYRING_GCP_PROJECT` environment variable
- [ ] Register MCP server in `.mcp.json`

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `KEYRING_GCP_PROJECT` | Yes | — | GCP project ID |
| `KEYRING_GCP_SA_KEY` | No | ADC | Path to service account key JSON |
| `KEYRING_GCP_PREFIX` | No | `keyring-` | Prefix for secret names in GCP |
| `KEYRING_GCP_CACHE_TTL` | No | `300` | Cache lifetime in seconds |

Example `.mcp.json` with GCP:

```json
{
  "mcpServers": {
    "keyring": {
      "command": "python",
      "args": ["tools/keyring/server.py"],
      "cwd": "<repo-root>/tools/keyring",
      "env": {
        "KEYRING_GCP_PROJECT": "coreforged-city"
      }
    }
  }
}
```

> 📎 **Memory — B-5 (E-1166):** The `keyring-` prefix is how your secrets coexist
> in a shared GCP project. The store strips the prefix internally, so the rest of
> the keyring sees bare names (`agentmail-api-key`, not `keyring-agentmail-api-key`).
> If you change the prefix, you need to re-upload secrets with the new prefix —
> existing GCP secrets under the old prefix won't be found.

### B-6: Verify GCP store works

- [ ] Run the verification command and confirm secrets are accessible

```bash
KEYRING_GCP_PROJECT=YOUR_PROJECT_ID python -c "
from secret_store import GCPSecretManagerStore
s = GCPSecretManagerStore('YOUR_PROJECT_ID')
names = s.list_names()
print(f'{len(names)} secrets found: {names[:5]}...')
"
```

**Expected:** A number > 0 followed by your secret names. If 0, check:
1. The secrets exist with the prefix: `gcloud secrets list --project=YOUR_PROJECT_ID --filter="name:keyring-"`
2. The authenticated identity has `secretmanager.secretAccessor` role

> 📎 **Memory — B-6 (E-1166):** If `list_names()` returns 0 but `gcloud secrets list`
> shows your secrets, the prefix mismatch is the most likely cause. The store only
> returns secrets whose GCP name starts with the configured prefix (default
> `keyring-`). The TTL cache (default 5 min) can also mask newly-created secrets —
> set `KEYRING_GCP_CACHE_TTL=0` for initial testing, then restore it after
> verification passes.

**You're done with Option B.** Continue below for optional features.

---

## Post-Setup (Optional)

These steps are independent — do any, all, or none.

### Skeleton Keyring (DC-1 Structural Fix)

- [ ] Generate the skeleton file (if not already present)

The skeleton file (`.secrets.skeleton.json`) provides the shape of the keyring — every key
name with a `<service:key-name>` placeholder — without values. Agents read the skeleton
to understand what's available. This is Construction Type 1: the skeleton IS the data
agents need, making reading `.secrets.json` unnecessary.

The skeleton is committed to git and safe to read in any context.

```bash
python consolidate.py sync-skeleton
```

> 📎 **Memory — Skeleton (E-1185):** The skeleton was a Construction Type 1 fix
> because prose rules saying "don't read .secrets.json" achieved 0% compliance —
> agents read it anyway because they needed to know the keyring's shape. The
> skeleton gives them that shape with zero values, making the safe path the useful
> path. This is the structural pattern: make the right thing the easy thing, don't
> mandate the right thing and hope.

### The `.secrets/` Directory

- [ ] Create a `.secrets/` directory for credential files (if using file-based secrets)

Place secret files (API keys, credentials, service account JSONs) in a `.secrets/`
directory. This directory should be gitignored and live outside the repo. Set the
`KEYRING_SECRETS_ROOT` environment variable to point at the parent of `.secrets/`
if it's not 3 directories up from the keyring.

Supported file types for ingest: `.txt`, `.env`, `.json`.

```bash
python consolidate.py ingest              # register all new files
python consolidate.py ingest --dry-run    # preview without changing anything
```

Ingest scans `.secrets/` for supported files, creates `PASTE_FROM:` references in
`.secrets.json` (values stay in the source files — not copied), adds entries to
`secret_manifest.json`, and auto-syncs the skeleton.

### Adding a New Secret (Three Paths)

**Path 1 — File-based (recommended):**
- [ ] Place the file in your `.secrets/` directory
- [ ] Run `python consolidate.py ingest`
- [ ] Edit `secret_manifest.json` to improve the description and service tag

**Path 2 — Interactive:**
- [ ] Run `python add_secret.py my-secret-name` (value read from stdin)
- [ ] Run `python consolidate.py sync-skeleton`

**Path 3 — Bulk discovery:**
- [ ] `python consolidate.py scan ~/projects` (find scattered credentials)
- [ ] `python consolidate.py migrate ~/projects -t .secrets/` (collect them)
- [ ] `python consolidate.py generate .secrets/` (generate keyring files)
- [ ] `python consolidate.py audit .secrets.json .secrets/` (verify sync)

---

## Health Monitoring

- [ ] Run `python key_monitor.py` (optional — confirms all services are reachable)

The keyring includes a health monitor that checks connectivity, tracks key rotation age,
and flags stale credentials. Run it on demand — no daemon, no OS scheduler. Works on
Windows, macOS, and Linux (pure Python stdlib).

### Commands

| Command | What it does |
|---------|-------------|
| `python key_monitor.py` | Run checks, log results, print status |
| `python key_monitor.py --status` | Print latest status without re-checking |
| `python key_monitor.py --json` | Output latest status as JSON (for dashboards) |
| `python key_monitor.py --html` | Generate self-contained HTML dashboard |
| `python key_monitor.py --html path/out.html` | Dashboard at a custom path |
| `python key_monitor.py --history 10` | Show last 10 check summaries from the log |

### Health States

| State | Meaning | Action |
|-------|---------|--------|
| **Healthy** | Connectivity passes, key age within threshold | None |
| **Stale** | Connectivity passes, but key age exceeds rotation threshold | Rotate the key |
| **Failing** | API returns error (401, 403, timeout) | Investigate — key may be revoked or permissions changed |
| **Empty** | No credential in the store for this service | Add the credential or confirm it's intentionally absent |

### Rotation Thresholds

| Category | Threshold | Examples |
|----------|-----------|----------|
| `bearer` | 90 days | API keys, bot tokens |
| `oauth-client` | 365 days | OAuth client secrets |
| `service-account` | 365 days | GCP/Firebase SA keys |
| `encryption` | 180 days | Field encryption keys |
| `jwt` | 180 days | JWT signing secrets |
| `url` | no expiry | Service URLs (track changes, not age) |

### Recommended Cadence

Run `python key_monitor.py` daily or at session start. The `--status` command shows
the latest snapshot without making API calls — use it for quick checks between full runs.

### Files Produced (All Gitignored)

| File | Purpose |
|------|---------|
| `health_log.jsonl` | Append-only check history (one JSON line per run) |
| `health_status.json` | Latest status snapshot (overwritten each run) |
| `key_rotation.json` | Hash-based rotation tracking (first_seen, last_changed per key) |
| `dashboard.html` | Self-contained HTML dashboard (regenerated on `--html`) |

### Integration with Other Tools

```python
import json, subprocess
result = subprocess.run(["python", "key_monitor.py", "--json"], capture_output=True, text=True)
status = json.loads(result.stdout)
failing = [s for s in status["services"] if s["health"] == "failing"]
```

---

## Keyring-Backed MCP Servers

The keyring can serve as the credential source for other MCP servers. Instead of
pasting raw tokens into each `.mcp.json`, write a launcher script that reads from
the keyring store and injects the credential as an environment variable.

### Supabase MCP Server

- [ ] (Optional) Set up keyring-backed Supabase MCP server

The Supabase MCP server (`@supabase/mcp-server-supabase`) needs a personal access
token (PAT) as `SUPABASE_ACCESS_TOKEN`. The keyring launcher handles this:

**1. Add the PAT to the keyring (one time):**

```bash
python add_secret.py supabase-access-token
# Paste your PAT from https://supabase.com/dashboard/account/tokens
```

**2. Point `.mcp.json` at the launcher:**

```json
{
  "mcpServers": {
    "supabase": {
      "command": "python",
      "args": ["tools/keyring/supabase_mcp_launcher.py"]
    }
  }
}
```

The launcher reads the token from `.secrets.json`, sets it as an environment variable,
and spawns the Supabase MCP server. The agent never sees the raw token — DC-1 compliant.

### Adding Launchers for Other MCP Servers

Follow the same pattern: a Python script that reads a secret by name, sets the
environment variable the MCP server expects, and `subprocess.run`s the server.
See `supabase_mcp_launcher.py` as a template.

---

## Permissions

`permissions.json` and `secret_manifest.json` travel with the repo (they contain no secret
values). They work identically with both backends. The agent's identity (DID or AgentMail
address) determines which secrets they can check out, regardless of where those secrets
are stored.

---

## Troubleshooting

**"No GCP credentials found"**
- Run `gcloud auth application-default login` or set `KEYRING_GCP_SA_KEY`.
- On Windows, check `%APPDATA%\gcloud\application_default_credentials.json` exists.

**"Failed to access secret X"**
- Check the secret exists with the prefix: `gcloud secrets list --project=YOUR_PROJECT_ID --filter="name:keyring-"`
- Check the authenticated identity has `secretmanager.secretAccessor` role.
- If you skipped the "Grant access" step during SA creation (B-2), the SA has zero roles — see Memory B-2 point 3.

**"0 secrets loaded" (local store)**
- Verify `.secrets.json` exists in the keyring directory.
- Verify it has entries (not just `{}`).
- If using `PASTE_FROM:` references, verify `KEYRING_SECRETS_ROOT` points to the right directory.

**"SKIP (PASTE_FROM file not found)" during seeding**
- `PASTE_FROM:` paths resolve against `KEYRING_SECRETS_ROOT` env var, or 3 dirs up from the keyring by default.
- Set `KEYRING_SECRETS_ROOT` to the parent of your `.secrets/` directory.

**`FileNotFoundError` when running `gcloud` from Python on Windows**
- `gcloud` on Windows is a `.cmd` batch wrapper, not a direct executable.
- Use `shell=True` in `subprocess.run()`, or call `gcloud.cmd` explicitly.
- `seed_gcp.py` handles this automatically.

**Stale cached values after rotation**
- The store caches for 5 minutes by default. Set `KEYRING_GCP_CACHE_TTL=0` to disable, or restart the MCP server.

**"google-cloud-secret-manager not installed"**
- Not required. The keyring uses the REST API directly. Install it for slightly faster list operations: `pip install google-cloud-secret-manager`.

---

## Security Reminders

- **DC-1**: Keys on the key ring, not in your mouth. Never print, log, or hold secret values in context.
- `.secrets.json` must be gitignored. Never commit it.
- `.secrets.skeleton.json` IS committed — it contains placeholders only, never values.
- Service account key files should be gitignored and stored outside the repo.
- Use the minimum IAM role: `Secret Manager Secret Accessor` (read-only). Never grant `Secret Manager Admin` to agent service accounts.
- The checkout ledger (`checkout_ledger.jsonl`) records every secret access. Review it periodically.
- Agents should read `.secrets.skeleton.json` for structure, never `.secrets.json` for values.

---

## Memory Index

This guide embeds experience from prior setup sessions. Each `📎 Memory` callout
references the source EAM (session log) or friction journal entry where the lesson
was learned.

| Step | Source | What It Covers |
|------|--------|---------------|
| A-2 | E-1185 | Extension whitelist for ingest (`.jpg` pollution) |
| A-4 | E-1185 | `PASTE_FROM:` path resolution and `KEYRING_SECRETS_ROOT` |
| B-1 | F-001 | API search ranking buries exact matches in GCP console |
| B-2 | F-002–F-005 | IAP confusion, SA list redirect, "optional" grant, opaque key names |
| B-3 | S-02 session | `PASTE_FROM` resolution, Windows `gcloud.cmd`, ALREADY_EXISTS handling |
| B-4 | E-1166 | Three auth paths, ADC file location on Windows |
| B-5 | E-1166 | Prefix stripping, re-upload requirement on prefix change |
| B-6 | E-1166 | Prefix mismatch debugging, TTL cache masking new secrets |
| Skeleton | E-1185 | Construction Type 1: why prose rules failed at 0% and structural fix works |

Friction journal entries (F-001 through F-005) are in `FRICTION_JOURNAL.md` in this repo.
EAM entries (E-NNNN) are session logs from the build team — referenced by number for
traceability, not included in this repo.
