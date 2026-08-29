# AGENTS.md — Agent Keyring

> Sovereign secrets infrastructure. Keys on the keyring, not in your mouth.

## What This Is

A complete secrets management toolkit for AI agent workstations. Agents check out
keys for authenticated API calls — keys never enter conversation context, tool results,
EAM entries, or logs. The MCP server makes the call and returns only the response data.

Two backends: local file store (single machine, zero setup) or GCP Secret Manager
(multi-machine federation, shared vault). Both use the same MCP interface.

## Architecture

```
Agent (Sofer, Mark42, etc.)
  │
  ├─ Identity: DID (did:key) or AgentMail fallback
  │
  ▼
Keyring MCP Server (server.py)
  │
  ├─ verify identity (identity.py)
  ├─ check permission (permissions.json)
  ├─ retrieve secret (secret_store.py → local or GCP)
  ├─ call service adapter (adapters/*.py)
  ├─ log checkout (ledger.py → checkout_ledger.jsonl)
  │
  ▼
Data returned (key never in context)
```

## Hard Constraint (DC-1)

Secret values MUST NOT appear in:
- MCP tool results
- Conversation context
- EAM entries or logs
- Git commits
- Command-line arguments (use stdin)

The keyring makes authenticated API calls and returns only the data. This is structural
(Construction Type 1), not a prose mandate — the skeleton file provides all the shape
data an agent needs without values.

## File Map

### Core (MCP Server)

| File | Purpose |
|------|---------|
| `server.py` | MCP server — 4 tools: list, request, history, affinity |
| `secret_store.py` | Pluggable backends: `LocalFileStore`, `GCPSecretManagerStore` |
| `identity.py` | DID + AgentMail identity verification |
| `ledger.py` | Append-only checkout ledger (JSONL) |
| `permissions.json` | Agent-to-secret ACL (who can check out what) |
| `secret_manifest.json` | Key names, descriptions, services — NO values |
| `.secrets.json` | Actual values — gitignored, DC-1 protected |
| `.secrets.skeleton.json` | Shape-only keyring — agents read THIS, never .secrets.json |

### Tools (CLI)

| File | Purpose |
|------|---------|
| `add_secret.py` | Add/update one secret via stdin (DC-1 safe) |
| `consolidate.py` | Scan, migrate, generate, audit, sync-skeleton, ingest |
| `connectivity_test.py` | Test each service with minimal health-check call |
| `key_monitor.py` | Track connectivity, rotation age, staleness, HTML dashboard |
| `taxonomy.py` | Agent archetypes, key shapes, service mapping, gap analysis |
| `populate_secrets.py` | Bulk population helper |
| `discover_supabase_pat.py` | Find Supabase PAT from local gcloud/browser state |
| `supabase_mcp_launcher.py` | Keyring-backed launcher for Supabase MCP server |

### Data (committed, no values)

| File | Purpose |
|------|---------|
| `taxonomy.json` | Key shapes, agent archetypes, service-to-archetype map |
| `ecosystem_registry.json` | 100+ services: key shapes, env vars, adapter patterns |
| `key_rotation.json` | Hash-based rotation tracking (gitignored) |
| `requirements.txt` | Python dependencies |
| `SETUP.md` | Full setup guide (local + GCP) |
| `AGENTS.md` | This file |

### Data (gitignored, machine-local)

| File | Purpose |
|------|---------|
| `.secrets.json` | Secret values — NEVER read by agents |
| `health_log.jsonl` | Append-only check history |
| `health_status.json` | Latest health snapshot |
| `checkout_ledger.jsonl` | Every secret checkout logged |
| `dashboard.html` | Self-contained HTML health dashboard |

### Adapters

| File | Service | Status |
|------|---------|--------|
| `adapters/ga4.py` | Google Analytics 4 Data API | Built |
| `adapters/__init__.py` | Adapter registry | Built |
| `server.py` (inline) | AgentMail REST API | Built |

## MCP Tools

The keyring exposes 4 tools via MCP:

| Tool | What It Does |
|------|-------------|
| `keyring_list_available` | Show secret names + descriptions the agent can access (never values) |
| `keyring_authenticated_request` | Make an API call using a managed secret — key stays in the server |
| `keyring_checkout_history` | Query the checkout ledger — who, what, when, why |
| `keyring_agent_affinity` | Analyze agent-service usage patterns from ledger data |

## Skeleton Keyring (DC-1 Structural Fix)

The skeleton (`.secrets.skeleton.json`) provides the shape of the keyring — every key
name with a `<service:key-name>` placeholder — without any values. Agents read the
skeleton to understand what's available. This is Construction Type 1: the skeleton IS
the data agents need, making reading `.secrets.json` unnecessary.

### Rebuilding the skeleton

```bash
python consolidate.py sync-skeleton
```

Reads `.secrets.json` keys (not values), cross-references `secret_manifest.json` for
service tags, writes `.secrets.skeleton.json` with placeholders. Run after adding or
removing secrets.

## Adding Secrets

### From a file (recommended)

1. Place the secret file in `C:\CrystallineCity\.secrets\` (gitignored directory)
2. Run ingest to register all new files:

```bash
python consolidate.py ingest              # register all new .secrets/ files
python consolidate.py ingest --dry-run    # preview what would be registered
```

Ingest scans for `.txt`, `.env`, `.json` files, creates `PASTE_FROM:` references in
`.secrets.json`, adds manifest entries, and auto-syncs the skeleton. The actual values
stay in the source files — they are not copied.

### Single secret (interactive)

```bash
python add_secret.py stripe-secret-key    # prompts for value (hidden input)
echo "sk_live_xxx" | python add_secret.py stripe-secret-key  # piped
```

Value is read from stdin, never from command-line args (DC-1 safe).

### Bulk discovery

```bash
python consolidate.py scan ~/projects     # find scattered credentials
python consolidate.py migrate ~/projects -t .secrets/  # collect into .secrets/
python consolidate.py generate .secrets/  # generate keyring files
python consolidate.py audit .secrets.json .secrets/     # verify sync
```

## Health Monitoring

```bash
python key_monitor.py              # run checks + log results
python key_monitor.py --status     # latest status (no API calls)
python key_monitor.py --json       # JSON output for dashboards
python key_monitor.py --html       # generate self-contained HTML dashboard
python key_monitor.py --history 10 # last 10 check summaries
```

Tests all services with minimal health-check calls, tracks key rotation via SHA-256
hashes (DC-1 safe — only hashes stored, never values), flags stale credentials.

## Taxonomy & Ecosystem

```bash
python taxonomy.py profile          # current keyring mapped to archetypes
python taxonomy.py gaps             # missing services per archetype
python taxonomy.py suggest stripe   # suggest archetype + key shape for a service
python taxonomy.py ecosystem        # browse full ecosystem registry
python taxonomy.py lookup sentry    # look up any service across taxonomy + ecosystem
```

The taxonomy maps keys to 6 agent archetypes (builder, analyst, operator, researcher,
communicator, guardian) and 6 key shapes (bearer, oauth, service_account, keypair,
derived, url). The ecosystem registry covers 100+ common services with key shapes,
env var conventions, and adapter patterns.

## Permissions

`permissions.json` maps agent identifiers to allowed secret names:

```json
{
  "sofer@agentmail.to": ["agentmail-api-key", "ga4-credentials", ...],
  "mark42@agentmail.to": ["agentmail-api-key", "supabase-url", ...],
  "_default": []
}
```

`"*"` grants access to all secrets (admin). `_default` applies when no matching
agent entry exists. When DID identity ships (EMBASSY2-213), identifiers switch from
AM addresses to `did:key:z6Mk...` — the permission file format stays the same.

## Keyring-Backed MCP Launchers

Other MCP servers can read credentials from the keyring instead of hardcoding tokens
in `.mcp.json`. Pattern: a Python script reads the secret by name, sets the expected
environment variable, and spawns the MCP server.

Built: `supabase_mcp_launcher.py` — injects `SUPABASE_ACCESS_TOKEN` from keyring.

## Setup

Full setup instructions (local file store + GCP Secret Manager): see `SETUP.md`.

Quick start:
1. `pip install mcp[cli]`
2. Place secrets in `.secrets/`, run `python consolidate.py ingest`
3. Add keyring to `.mcp.json` (see SETUP.md)
4. Agents use `keyring_list_available` and `keyring_authenticated_request`

## EPIC-KEYRING-220 Stories

| Story | Title | Status |
|-------|-------|--------|
| S-01 | GCP Project Setup | park |
| S-02 | Seed Secret Manager | park |
| S-03 | Build Keyring MCP Server | built (local phase 1) |
| S-04 | Agent Identity Verification | built (AM fallback) |
| S-05 | GA4 Data API Integration | built |
| S-06 | Wire into CLAUDE.md Files | done |
| S-07 | Cross-Machine Federation | park |
| S-08 | Product Packaging | park |
| S-09 | Checkout Ledger | built |
| S-10 | Usage Pattern Analytics | park |
| S-11 | Context Overload Signal | park |
| S-12 | Key Taxonomy | done |
| S-13 | Universal Key Registry | done |
