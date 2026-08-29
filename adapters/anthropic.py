"""Anthropic API adapter for Agent Keyring.

Supports: Messages API (chat completions), model listing.
The secret is an Anthropic API key (sk-ant-...).
"""

import json
import urllib.error
import urllib.request

ANTHROPIC_API_BASE = "https://api.anthropic.com/v1"
DEFAULT_API_VERSION = "2023-06-01"


def anthropic_adapter(
    secret: str,
    method: str = "POST",
    endpoint: str = "",
    params: dict | None = None,
    body: dict | None = None,
) -> dict:
    """Anthropic REST API adapter.

    The `params` dict carries:
      action:    'messages' (default), 'models', 'models/list'
      model:     Model ID (default: 'claude-sonnet-4-20250514')
      messages:  List of message dicts [{"role": "user", "content": "..."}]
      max_tokens: Max response tokens (default 1024)
      system:    System prompt string
      temperature: Sampling temperature (0-1)
    """
    params = params or {}

    action = params.pop("action", "") or endpoint.strip("/") or "messages"

    if action in ("models", "models/list"):
        return _list_models(secret)

    if action == "messages":
        return _send_message(secret, params, body)

    return {"error": f"Unknown action '{action}'. Supported: 'messages', 'models'."}


def _send_message(secret: str, params: dict, body: dict | None) -> dict:
    if body is None:
        messages = params.get("messages", [])
        if not messages:
            return {"error": "Missing 'messages' in params."}
        body = {
            "model": params.get("model", "claude-sonnet-4-20250514"),
            "max_tokens": params.get("max_tokens", 1024),
            "messages": messages,
        }
        if params.get("system"):
            body["system"] = params["system"]
        if params.get("temperature") is not None:
            body["temperature"] = params["temperature"]

    url = f"{ANTHROPIC_API_BASE}/messages"
    data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "x-api-key": secret.strip(),
            "anthropic-version": DEFAULT_API_VERSION,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            response_data = json.loads(resp.read().decode("utf-8"))
            content_blocks = response_data.get("content", [])
            text = "".join(
                b.get("text", "") for b in content_blocks if b.get("type") == "text"
            )
            return {
                "status": resp.status,
                "data": {
                    "text": text,
                    "model": response_data.get("model", ""),
                    "stop_reason": response_data.get("stop_reason", ""),
                    "usage": response_data.get("usage", {}),
                },
            }
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")[:1000]
        return {"status": e.code, "error": body_text}
    except (urllib.error.URLError, TimeoutError) as e:
        return {"error": str(e)}


def _list_models(secret: str) -> dict:
    url = f"{ANTHROPIC_API_BASE}/models"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "x-api-key": secret.strip(),
            "anthropic-version": DEFAULT_API_VERSION,
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            response_data = json.loads(resp.read().decode("utf-8"))
            models = response_data.get("data", [])
            return {
                "status": resp.status,
                "data": [
                    {"id": m.get("id", ""), "display_name": m.get("display_name", "")}
                    for m in models
                ],
                "count": len(models),
            }
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")[:1000]
        return {"status": e.code, "error": body_text}
    except (urllib.error.URLError, TimeoutError) as e:
        return {"error": str(e)}
