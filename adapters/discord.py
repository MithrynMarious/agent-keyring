"""Discord API adapter for Agent Keyring.

Supports: channel messages, guild info, webhooks.
The secret is a Discord bot token.
"""

import json
import urllib.error
import urllib.parse
import urllib.request

DISCORD_API_BASE = "https://discord.com/api/v10"


def discord_adapter(
    secret: str,
    method: str = "GET",
    endpoint: str = "",
    params: dict | None = None,
    body: dict | None = None,
) -> dict:
    """Discord REST API adapter.

    The `params` dict carries:
      action:      'messages', 'channels', 'guilds', 'webhook', 'user'
      channel_id:  Channel snowflake ID (for messages)
      guild_id:    Guild snowflake ID (for guilds/channels)
      webhook_url: Full webhook URL (for webhook action)
      limit:       Max messages to fetch (default 50, max 100)
      content:     Message text (for sending messages)
    """
    params = params or {}

    action = params.pop("action", "") or endpoint.strip("/")
    channel_id = params.pop("channel_id", "")
    guild_id = params.pop("guild_id", "")
    webhook_url = params.pop("webhook_url", "")
    limit = params.pop("limit", 50)
    content = params.pop("content", "")

    if action == "webhook" and webhook_url:
        return _send_webhook(webhook_url, content or (body or {}).get("content", ""), body)

    if action == "user":
        url = f"{DISCORD_API_BASE}/users/@me"
    elif action == "guilds":
        if guild_id:
            url = f"{DISCORD_API_BASE}/guilds/{guild_id}"
        else:
            url = f"{DISCORD_API_BASE}/users/@me/guilds"
    elif action == "channels":
        if channel_id:
            url = f"{DISCORD_API_BASE}/channels/{channel_id}"
        elif guild_id:
            url = f"{DISCORD_API_BASE}/guilds/{guild_id}/channels"
        else:
            return {"error": "Missing 'channel_id' or 'guild_id' for channels action."}
    elif action == "messages":
        if not channel_id:
            return {"error": "Missing 'channel_id' for messages action."}
        if content or (body and body.get("content")):
            url = f"{DISCORD_API_BASE}/channels/{channel_id}/messages"
            method = "POST"
            body = body or {"content": content}
        else:
            url = f"{DISCORD_API_BASE}/channels/{channel_id}/messages?limit={limit}"
    elif endpoint:
        url = f"{DISCORD_API_BASE}/{endpoint.lstrip('/')}"
    else:
        return {"error": "Missing 'action'. Supported: messages, channels, guilds, webhook, user."}

    headers = {
        "Authorization": f"Bot {secret.strip()}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    data = json.dumps(body).encode("utf-8") if body and method != "GET" else None

    req = urllib.request.Request(url, data=data, method=method, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            response_data = json.loads(resp.read().decode("utf-8"))
            result = {"status": resp.status, "data": response_data}
            if isinstance(response_data, list):
                result["count"] = len(response_data)
            return result
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")[:1000]
        return {"status": e.code, "error": body_text}
    except (urllib.error.URLError, TimeoutError) as e:
        return {"error": str(e)}


def _send_webhook(webhook_url: str, content: str, body: dict | None) -> dict:
    """Send a message via Discord webhook (no bot token needed)."""
    if not content and not body:
        return {"error": "Missing 'content' for webhook message."}

    payload = body or {"content": content}
    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        webhook_url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status == 204:
                return {"status": 204, "data": {"sent": True}}
            response_data = json.loads(resp.read().decode("utf-8"))
            return {"status": resp.status, "data": response_data}
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")[:1000]
        return {"status": e.code, "error": body_text}
    except (urllib.error.URLError, TimeoutError) as e:
        return {"error": str(e)}
