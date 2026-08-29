"""Generic REST adapter for Agent Keyring.

Handles the three dominant auth patterns (Bearer, API-key header, Basic)
so any service with a standard REST API can be used without a custom adapter.
Service-specific adapters override this when the API requires non-standard auth
(OAuth2 refresh, HMAC signing, GCP service accounts, form-encoded bodies).
"""

import base64
import json
import urllib.error
import urllib.parse
import urllib.request


AUTH_BEARER = "bearer"
AUTH_HEADER = "header"
AUTH_BASIC = "basic"
AUTH_QUERY = "query"

SERVICE_REGISTRY = {
    "slack": {
        "base_url": "https://slack.com/api",
        "auth": AUTH_BEARER,
        "content_type": "application/json; charset=utf-8",
    },
    "notion": {
        "base_url": "https://api.notion.com/v1",
        "auth": AUTH_BEARER,
        "extra_headers": {"Notion-Version": "2022-06-28"},
    },
    "linear": {
        "base_url": "https://api.linear.app",
        "auth": AUTH_BEARER,
    },
    "vercel": {
        "base_url": "https://api.vercel.com",
        "auth": AUTH_BEARER,
    },
    "cloudflare": {
        "base_url": "https://api.cloudflare.com/client/v4",
        "auth": AUTH_BEARER,
    },
    "sentry": {
        "base_url": "https://sentry.io/api/0",
        "auth": AUTH_BEARER,
    },
    "datadog": {
        "base_url": "https://api.datadoghq.com/api/v2",
        "auth": AUTH_HEADER,
        "auth_header": "DD-API-KEY",
    },
    "sendgrid": {
        "base_url": "https://api.sendgrid.com/v3",
        "auth": AUTH_BEARER,
    },
    "twilio": {
        "base_url": "https://api.twilio.com/2010-04-01",
        "auth": AUTH_BASIC,
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "auth": AUTH_BEARER,
    },
    "huggingface": {
        "base_url": "https://huggingface.co/api",
        "auth": AUTH_BEARER,
    },
    "elevenlabs": {
        "base_url": "https://api.elevenlabs.io/v1",
        "auth": AUTH_HEADER,
        "auth_header": "xi-api-key",
    },
    "replicate": {
        "base_url": "https://api.replicate.com/v1",
        "auth": AUTH_BEARER,
    },
    "pinecone": {
        "base_url": "https://api.pinecone.io",
        "auth": AUTH_HEADER,
        "auth_header": "Api-Key",
    },
    "deepgram": {
        "base_url": "https://api.deepgram.com/v1",
        "auth": AUTH_BEARER,
    },
    "cohere": {
        "base_url": "https://api.cohere.com/v2",
        "auth": AUTH_BEARER,
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "auth": AUTH_BEARER,
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "auth": AUTH_BEARER,
    },
    "mistral": {
        "base_url": "https://api.mistral.ai/v1",
        "auth": AUTH_BEARER,
    },
    "telegram": {
        "base_url": "https://api.telegram.org",
        "auth": AUTH_QUERY,
        "auth_param": "bot_token",
        "url_template": "https://api.telegram.org/bot{secret}/{endpoint}",
    },
    "airtable": {
        "base_url": "https://api.airtable.com/v0",
        "auth": AUTH_BEARER,
    },
    "typesense": {
        "base_url": "http://localhost:8108",
        "auth": AUTH_HEADER,
        "auth_header": "X-TYPESENSE-API-KEY",
    },
    "mongodb": {
        "base_url": "https://cloud.mongodb.com/api/atlas/v2",
        "auth": AUTH_BASIC,
    },
    "aws": {
        "base_url": "https://sts.amazonaws.com",
        "auth": AUTH_HEADER,
        "auth_header": "X-Api-Key",
        "note": "AWS SigV4 requires a dedicated adapter for full support. Generic handles simple API Gateway endpoints with API key auth.",
    },
    "azure": {
        "base_url": "https://management.azure.com",
        "auth": AUTH_BEARER,
        "note": "Azure AD OAuth flows require a dedicated adapter. Generic handles pre-obtained bearer tokens.",
    },
    "google-ai": {
        "base_url": "https://generativelanguage.googleapis.com/v1",
        "auth": AUTH_QUERY,
        "auth_param": "key",
    },
}


def generic_adapter(
    secret: str,
    method: str = "GET",
    endpoint: str = "",
    params: dict | None = None,
    body: dict | None = None,
    *,
    service_config: dict | None = None,
) -> dict:
    """Generic REST API adapter.

    Works for any service in SERVICE_REGISTRY, or with a custom
    service_config dict passed directly.

    The `params` dict carries:
      base_url:  Override the registry's base URL
      Any other keys are passed as query parameters.
    """
    params = params or {}
    config = service_config or {}

    base_url = params.pop("base_url", None) or config.get("base_url", "")
    if not base_url:
        return {"error": "No base_url configured. Pass base_url in params or register the service."}

    auth_type = config.get("auth", AUTH_BEARER)
    auth_header_name = config.get("auth_header", "Authorization")
    extra_headers = config.get("extra_headers", {})
    content_type = config.get("content_type", "application/json")

    url_template = config.get("url_template")
    if url_template:
        url = url_template.format(secret=secret.strip(), endpoint=endpoint.lstrip("/"))
    else:
        url = f"{base_url}/{endpoint.lstrip('/')}" if endpoint else base_url

    if method == "GET" and params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)

    headers = {
        "Content-Type": content_type,
        "Accept": "application/json",
    }
    headers.update(extra_headers)

    if auth_type == AUTH_BEARER:
        headers["Authorization"] = f"Bearer {secret.strip()}"
    elif auth_type == AUTH_HEADER:
        headers[auth_header_name] = secret.strip()
    elif auth_type == AUTH_BASIC:
        auth_b64 = base64.b64encode(f"{secret.strip()}:".encode()).decode()
        headers["Authorization"] = f"Basic {auth_b64}"
    elif auth_type == AUTH_QUERY:
        param_name = config.get("auth_param", "key")
        sep = "&" if "?" in url else "?"
        if not url_template:
            url += f"{sep}{param_name}={urllib.parse.quote(secret.strip())}"

    data = json.dumps(body).encode("utf-8") if body and method != "GET" else None

    req = urllib.request.Request(url, data=data, method=method, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            try:
                response_data = json.loads(raw)
            except json.JSONDecodeError:
                response_data = {"raw": raw[:2000]}
            result = {"status": resp.status, "data": response_data}
            if isinstance(response_data, list):
                result["count"] = len(response_data)
            return result
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")[:1000]
        return {"status": e.code, "error": body_text}
    except (urllib.error.URLError, TimeoutError) as e:
        return {"error": str(e)}


def make_adapter(service_name: str):
    """Create a bound adapter function for a registered service."""
    config = SERVICE_REGISTRY.get(service_name)
    if not config:
        return None

    def adapter(secret, method="GET", endpoint="", params=None, body=None):
        return generic_adapter(
            secret, method, endpoint, params, body,
            service_config=config,
        )

    adapter.__doc__ = f"Generic adapter for {service_name} ({config.get('base_url', 'custom')})"
    adapter.__name__ = f"{service_name}_adapter"
    return adapter
