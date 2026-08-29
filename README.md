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

## License

Proprietary — CoreForged LLC. See AGENTS.md for terms.
