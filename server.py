"""Keyring MCP server — sovereign secrets infrastructure for the Crystalline City.

EPIC-KEYRING-220 S-03. Agents check out keys; keys never enter context.
Identity: DID primary, AgentMail fallback (DC-2).
Checkout ledger: append-only JSONL for organizational intelligence (DC-6).

Architecture: Agent DID → Keyring MCP → verify identity → check permission →
              retrieve secret → make authenticated API call → return data only →
              log checkout to ledger.
"""

import json
import os
import sys
import logging
from mcp.server.fastmcp import FastMCP

# Ensure keyring package dir is on the path so relative imports work
# regardless of which directory the MCP launcher starts us from.
_KEYRING_DIR_FOR_PATH = os.path.dirname(os.path.abspath(__file__))
if _KEYRING_DIR_FOR_PATH not in sys.path:
    sys.path.insert(0, _KEYRING_DIR_FOR_PATH)

from identity import resolve_identity, VerifyMethod
from secret_store import LocalFileStore, GCPSecretManagerStore, SecretStore
from ledger import record_checkout, query_ledger, agent_affinity_report

logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")
log = logging.getLogger("keyring")

KEYRING_DIR = os.path.dirname(os.path.abspath(__file__))
PERMISSIONS_PATH = os.path.join(KEYRING_DIR, "permissions.json")
MANIFEST_PATH = os.path.join(KEYRING_DIR, "secret_manifest.json")
DID_REGISTRY_PATH = os.path.join(KEYRING_DIR, "did_registry.json")

# Store selection: GCP Secret Manager when KEYRING_GCP_PROJECT is set, else local file.
_GCP_PROJECT = os.environ.get("KEYRING_GCP_PROJECT")

if _GCP_PROJECT:
    store: SecretStore = GCPSecretManagerStore(
        project_id=_GCP_PROJECT,
        sa_key_path=os.environ.get("KEYRING_GCP_SA_KEY"),
        prefix=os.environ.get("KEYRING_GCP_PREFIX", "keyring-"),
        cache_ttl=int(os.environ.get("KEYRING_GCP_CACHE_TTL", "300")),
    )
    log.info("Using GCP Secret Manager store (project: %s)", _GCP_PROJECT)
else:
    SECRET_STORE_PATH = os.environ.get(
        "KEYRING_SECRET_STORE",
        os.path.join(KEYRING_DIR, ".secrets.json"),
    )
    store: SecretStore = LocalFileStore(SECRET_STORE_PATH)

mcp = FastMCP(
    "keyring",
    instructions=(
        "Agent Keyring — sovereign secrets infrastructure. "
        "Check out keys for authenticated API calls. Keys never appear in tool results. "
        "Use keyring_list_available to see what's accessible, "
        "keyring_authenticated_request to make API calls with managed credentials, "
        "and keyring_checkout_history to review access patterns."
    ),
)


def _load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _check_permission(agent_id: str, secret_name: str) -> bool:
    """Check if agent has permission to access a secret."""
    perms = _load_json(PERMISSIONS_PATH)
    allowed = perms.get(agent_id, perms.get("_default", []))
    return "*" in allowed or secret_name in allowed


def _resolve_caller(
    did: str | None = None,
    agentmail_token: str | None = None,
    agentmail_inbox: str | None = None,
):
    """Resolve and verify the calling agent's identity."""
    registry_path = DID_REGISTRY_PATH if os.path.exists(DID_REGISTRY_PATH) else None
    return resolve_identity(
        did=did,
        agentmail_token=agentmail_token,
        agentmail_inbox=agentmail_inbox,
        did_registry_path=registry_path,
    )


@mcp.tool()
def keyring_list_available(
    did: str | None = None,
    agentmail_inbox: str | None = None,
) -> dict:
    """List secrets the calling agent can access. Returns names and descriptions only — never values.

    Args:
        did: Agent's DID (did:key:...) for identity verification.
        agentmail_inbox: Agent's AgentMail address (e.g. sofer@agentmail.to) as fallback identity.
    """
    manifest = _load_json(MANIFEST_PATH)
    secrets = manifest.get("secrets", {})
    perms = _load_json(PERMISSIONS_PATH)

    agent_id = did or agentmail_inbox or "unknown"
    allowed = perms.get(agent_id, perms.get("_default", []))

    available = {}
    for name, info in secrets.items():
        if "*" in allowed or name in allowed:
            available[name] = {
                "description": info.get("description", ""),
                "service": info.get("service", ""),
            }

    return {
        "agent": agent_id,
        "available_secrets": available,
        "count": len(available),
    }


@mcp.tool()
def keyring_authenticated_request(
    service: str,
    secret_name: str,
    method: str = "GET",
    endpoint: str = "",
    params: dict | None = None,
    body: dict | None = None,
    scope: str | None = None,
    purpose: str | None = None,
    did: str | None = None,
    agentmail_token: str | None = None,
    agentmail_inbox: str | None = None,
) -> dict:
    """Make an authenticated API call using a managed secret. The key never appears in the response.

    The keyring retrieves the secret, makes the API call, and returns only the response data.
    Every call is logged to the checkout ledger.

    Args:
        service: Service identifier (e.g. 'agentmail', 'stripe', 'ga4', 'firebase').
        secret_name: Name of the secret to use (from keyring_list_available).
        method: HTTP method (GET, POST, PUT, DELETE).
        endpoint: API endpoint path (appended to service base URL).
        params: Query parameters for the request.
        body: JSON body for POST/PUT requests.
        scope: Optional scope for multi-value keys (e.g. 'fleet', 'mcp'). When set, tries secret_name:scope first, falls back to secret_name.
        purpose: Why this request is being made (logged to ledger).
        did: Agent's DID for identity verification.
        agentmail_token: AgentMail API key for identity fallback.
        agentmail_inbox: Agent's AgentMail address for identity fallback.
    """
    identity = _resolve_caller(did, agentmail_token, agentmail_inbox)

    if identity.method == VerifyMethod.UNVERIFIED:
        return {"error": "Identity verification failed. Provide a valid DID or AgentMail credentials."}

    if not _check_permission(identity.agent_id, secret_name):
        return {
            "error": f"Agent {identity.agent_id} does not have permission to access '{secret_name}'.",
            "hint": "Check permissions.json or request access from the Magistrate.",
        }

    secret_value = store.get(secret_name, scope=scope)
    if secret_value is None:
        hint = f" (scope: {scope})" if scope else ""
        return {"error": f"Secret '{secret_name}'{hint} not found in store."}

    record_checkout(
        agent_id=identity.agent_id,
        verify_method=identity.method.value,
        secret_name=secret_name,
        service=service,
        purpose=purpose,
        params=params,
    )

    try:
        adapter = _get_adapter(service)
        if adapter is None:
            return {"error": f"No adapter registered for service '{service}'."}

        result = adapter(
            secret=secret_value,
            method=method,
            endpoint=endpoint,
            params=params,
            body=body,
        )
        return result
    except Exception as e:
        log.error("Request to %s failed: %s", service, e)
        return {"error": f"Request failed: {type(e).__name__}: {e}"}


@mcp.tool()
def keyring_checkout_history(
    agent_id: str | None = None,
    service: str | None = None,
    secret_name: str | None = None,
    days: int = 30,
) -> dict:
    """Query the checkout ledger — who accessed what, when, and why.

    Args:
        agent_id: Filter by agent (DID or AM address).
        service: Filter by service name.
        secret_name: Filter by secret name.
        days: How far back to look (default 30).
    """
    entries = query_ledger(
        agent_id=agent_id,
        service=service,
        secret_name=secret_name,
        days=days,
    )
    return {
        "count": len(entries),
        "entries": entries[-50:],  # cap response size
        "truncated": len(entries) > 50,
    }


@mcp.tool()
def keyring_agent_affinity(days: int = 30) -> dict:
    """Analyze agent-service affinity patterns from the checkout ledger.

    Returns which agents use which services most — the raw data for
    workstation specialization analysis and context overload detection.

    Args:
        days: How far back to analyze (default 30).
    """
    return agent_affinity_report(days=days)


# --- Service Adapters ---

_adapters: dict = {}


def _get_adapter(service: str):
    if not _adapters:
        _load_adapters()
    return _adapters.get(service)


def _load_adapters():
    """Load service adapters from the adapters/ directory."""
    _adapters["agentmail"] = _agentmail_adapter

    try:
        from adapters.ga4 import ga4_adapter
        _adapters["ga4"] = ga4_adapter
    except ImportError:
        log.warning("GA4 adapter not available (missing cryptography or adapters/ga4.py)")

    try:
        from adapters.stripe import stripe_adapter
        _adapters["stripe"] = stripe_adapter
    except ImportError:
        log.warning("Stripe adapter not available")

    try:
        from adapters.supabase import supabase_adapter
        _adapters["supabase"] = supabase_adapter
    except ImportError:
        log.warning("Supabase adapter not available")

    try:
        from adapters.anthropic import anthropic_adapter
        _adapters["anthropic"] = anthropic_adapter
    except ImportError:
        log.warning("Anthropic adapter not available")

    try:
        from adapters.github import github_adapter
        _adapters["github"] = github_adapter
    except ImportError:
        log.warning("GitHub adapter not available")

    try:
        from adapters.discord import discord_adapter
        _adapters["discord"] = discord_adapter
    except ImportError:
        log.warning("Discord adapter not available")

    try:
        from adapters.generic import SERVICE_REGISTRY, make_adapter
        for svc_name in SERVICE_REGISTRY:
            if svc_name not in _adapters:
                _adapters[svc_name] = make_adapter(svc_name)
        log.info("Generic adapters loaded for %d services", len(SERVICE_REGISTRY))
    except ImportError:
        log.warning("Generic adapter not available")


def _agentmail_adapter(
    secret: str,
    method: str = "GET",
    endpoint: str = "",
    params: dict | None = None,
    body: dict | None = None,
) -> dict:
    """AgentMail REST API adapter."""
    import urllib.request
    import urllib.error
    import urllib.parse

    base = "https://api.agentmail.to"
    url = f"{base}/{endpoint.lstrip('/')}" if endpoint else base

    if params:
        url += "?" + urllib.parse.urlencode(params)

    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            response_data = json.loads(resp.read().decode("utf-8"))
            return {"status": resp.status, "data": response_data}
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")[:500]
        return {"status": e.code, "error": body_text}
    except (urllib.error.URLError, TimeoutError) as e:
        return {"error": str(e)}


def main():
    mcp.run()


if __name__ == "__main__":
    main()
