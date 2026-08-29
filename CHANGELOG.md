# Changelog

All notable changes to Agent Keyring will be documented in this file.

## [0.1.0] — 2026-08-29

### Added
- MCP server with 4 tools: `keyring_list_available`, `keyring_authenticated_request`, `keyring_checkout_history`, `keyring_agent_affinity`
- Local file store backend (`.secrets.json` with `PASTE_FROM:` references)
- GCP Secret Manager backend (service account, ADC, and GCE metadata auth)
- 7 service adapters: AgentMail, GA4, Stripe, Supabase, Anthropic, GitHub, Discord
- Identity verification (DID primary, AgentMail fallback)
- Append-only checkout ledger with agent affinity analysis
- Per-agent, per-secret permissions (`permissions.json`)
- Key health monitor with HTML dashboard
- Service taxonomy (6 archetypes, 60+ ecosystem entries)
- Test suite (43 tests: store, permissions, adapter contracts, DC-1 compliance)
- PEP 621 packaging (`pyproject.toml`, `pip install .`)
- Setup guide with embedded lessons from prior setups (Seidrbook method)
- Friction journal documenting GCP console gotchas
- GitHub Actions CI (test on push/PR)
- Docker support (`Dockerfile` + `docker-compose.yml`)
