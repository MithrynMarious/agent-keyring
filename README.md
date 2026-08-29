# Agent Keyring

An MCP server that holds secrets and makes authenticated API calls on behalf of AI agents — so API keys never enter conversation context.

```
Agent → Keyring MCP → retrieve secret → make API call → return data only
```

The agent says *what* to do ("query GA4 for sessions"). The keyring handles *how* to authenticate. Keys stay on the keyring, never in the agent's mouth.

## Quickstart

```bash
# 1. Clone
git clone https://github.com/MithrynMarious/agent-keyring.git
cd agent-keyring

# 2. Install
pip install .

# 3. Copy the skeleton and fill in your keys
cp .secrets.skeleton.json .secrets.json
# Edit .secrets.json — replace placeholders with real values

# 4. Add to your MCP config (.mcp.json or Claude Desktop settings)
```

Add to your MCP config file:

**Claude Code** — `.mcp.json` in your project root:
```json
{
  "mcpServers": {
    "keyring": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "/path/to/agent-keyring"
    }
  }
}
```

**Claude Desktop** — config file location varies by OS:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

Same JSON format — add the `keyring` entry to your existing `mcpServers` block.

```bash
# 5. Verify
python -c "from secret_store import LocalFileStore; s = LocalFileStore('.secrets.json'); print(f'{len(s.list_names())} secrets loaded')"
```

## What's Working

| Component | Status | Notes |
|-----------|--------|-------|
| Local file store | **Active** | `.secrets.json` backend, PASTE_FROM references |
| GCP Secret Manager store | **Active** | Multi-machine, 3 auth paths (SA key, ADC, GCE metadata) |
| GA4 adapter | **Active** | OAuth + service account JWT, report formatting |
| AgentMail adapter | **Active** | Bearer token auth, inbox/thread operations |
| Stripe adapter | **Active** | Charges, customers, subscriptions (read-only) |
| Supabase adapter | **Active** | Table queries via PostgREST, auth admin |
| Anthropic adapter | **Active** | Messages API, model listing |
| GitHub adapter | **Active** | Repos, issues, PRs via REST API |
| Discord adapter | **Active** | Channel messages, webhooks |
| Identity verification | **Active** | DID primary, AgentMail fallback |
| Checkout ledger | **Active** | Append-only JSONL, agent affinity analysis |
| Key health monitor | **Active** | Connectivity checks, rotation tracking, HTML dashboard |
| Service taxonomy | **Active** | 6 archetypes, 60+ ecosystem entries |
| Permissions | **Active** | Per-agent, per-secret access control |

## MCP Tools

| Tool | What It Does |
|------|-------------|
| `keyring_list_available` | List secrets the agent can access (names only, never values) |
| `keyring_authenticated_request` | Make an API call using a managed secret |
| `keyring_checkout_history` | Query who accessed what, when, and why |
| `keyring_agent_affinity` | Analyze agent-service usage patterns |

## Security Model (DC-1)

Secret values never appear in:
- MCP tool results
- Conversation context
- Log output
- EAM entries or session records

The keyring makes the authenticated API call and returns only the response data. The checkout ledger logs every access (who, what, when, why) without recording the secret value.

## Docs

- **[SETUP.md](SETUP.md)** — Full setup guide with GCP migration, troubleshooting, and embedded lessons from prior setups
- **[FRICTION_JOURNAL.md](FRICTION_JOURNAL.md)** — GCP console gotchas (training-data-vs-reality deltas)
- **[AGENTS.md](AGENTS.md)** — Engineering posture and conventions

## Adding Secrets

```bash
# Interactive (value from stdin, never CLI args)
python add_secret.py my-api-key

# From files
mkdir -p .secrets
# Place key files in .secrets/
python consolidate.py ingest

# Bulk discovery
python consolidate.py scan ~/projects    # find scattered creds
python consolidate.py migrate ~/projects --target .secrets/
```

## GCP Backend (Multi-Machine)

For shared secrets across machines, use GCP Secret Manager as the backend:

```json
{
  "mcpServers": {
    "keyring": {
      "command": "python",
      "args": ["server.py"],
      "env": { "KEYRING_GCP_PROJECT": "your-project-id" }
    }
  }
}
```

See [SETUP.md](SETUP.md) Option B for the full GCP walkthrough.

## Registering Agents

New agents are denied access by default (DC-1). To grant an agent access to secrets, add an entry to `permissions.json`:

```json
{
  "agent-name@agentmail.to": ["secret-name-1", "secret-name-2"],
  "admin-agent@agentmail.to": ["*"],
  "_default": []
}
```

- Each key is an agent identifier (AgentMail address or DID)
- Values list the secret names the agent can check out
- `"*"` grants access to all secrets
- `"_default": []` means unregistered agents get nothing — this is the DC-1 structural default

When an unregistered agent calls `keyring_list_available`, it sees an empty list. The checkout ledger still records the attempt.

## Environment Variables

See [`.env.example`](.env.example) for the complete list. Key variables:

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `KEYRING_GCP_PROJECT` | For GCP backend | — | Selects GCP Secret Manager over local file |
| `KEYRING_SECRET_STORE` | No | `.secrets.json` | Local store file path |
| `KEYRING_SECRETS_ROOT` | No | 3 dirs up | Root for `PASTE_FROM:` path resolution |
| `GOOGLE_APPLICATION_CREDENTIALS` | For GCP SA auth | — | GCP service account key file |

## Logging

The server uses Python's `logging` module. Set the log level via environment:

```bash
# See all keyring activity
LOGLEVEL=DEBUG python server.py

# Quiet mode (errors only)
LOGLEVEL=ERROR python server.py
```

Default level is `WARNING`. The `keyring.store` and `keyring.ledger` loggers are the most useful for debugging auth and access issues.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `0 secrets loaded` | `.secrets.json` missing or empty | Copy `.secrets.skeleton.json` to `.secrets.json` and fill in values |
| `PASTE_FROM file not found` | `KEYRING_SECRETS_ROOT` not set or wrong | Set it to the parent directory of your `.secrets/` folder |
| `No adapter registered for service` | Service name doesn't match a registered adapter | Check `keyring_list_available` output for exact service names |
| Agent sees empty list | Agent not in `permissions.json` | Add the agent's identifier to `permissions.json` with allowed secrets |
| GCP `403 Permission denied` | Service account lacks Secret Manager access | Grant `roles/secretmanager.secretAccessor` to the SA in GCP console |
| GCP `404 Secret not found` | Wrong prefix or secret name | Check `KEYRING_GCP_PREFIX` — secret is stored as `{prefix}{name}` in GCP |
| Stale secret value from GCP | Cache TTL hasn't expired | Set `KEYRING_GCP_CACHE_TTL=0` or restart the server |
| `401` from adapter API call | Secret value is expired or invalid | Rotate the key in `.secrets.json` or GCP, then restart |

For GCP-specific setup issues, see [SETUP.md](SETUP.md) and [FRICTION_JOURNAL.md](FRICTION_JOURNAL.md).

## Docker

```bash
# Local file store
docker compose up keyring

# GCP backend
KEYRING_GCP_PROJECT=your-project docker compose --profile gcp up keyring-gcp
```

Mount your `.secrets.json` and `permissions.json` as volumes. See `docker-compose.yml` for the full configuration.

## CI

Tests run on push and PR via GitHub Actions across Python 3.12–3.13 on Linux, Windows, and macOS. See `.github/workflows/test.yml`.

## License

Proprietary — CoreForged LLC. See [LICENSE](LICENSE) for terms.
