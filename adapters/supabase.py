"""Supabase adapter for Agent Keyring.

Supports PostgREST table queries and Auth Admin operations.
The secret can be a service role key or an access token.
The supabase-url secret provides the project URL.
"""

import json
import urllib.error
import urllib.parse
import urllib.request


def supabase_adapter(
    secret: str,
    method: str = "GET",
    endpoint: str = "",
    params: dict | None = None,
    body: dict | None = None,
) -> dict:
    """Supabase REST API adapter.

    The `params` dict carries:
      url:       Supabase project URL (required — or pass as the secret if URL-typed)
      table:     Table name for PostgREST queries
      select:    Column selection (e.g. 'id,name,email')
      filters:   Dict of column=value filters (e.g. {'status': 'active'})
      limit:     Max rows (default 100)
      offset:    Pagination offset
      order:     Order by column (e.g. 'created_at.desc')
      rpc:       RPC function name (for stored procedures)
    """
    params = params or {}

    supabase_url = params.pop("url", "").rstrip("/")
    if not supabase_url:
        return {"error": "Missing 'url' in params — provide the Supabase project URL."}

    table = params.pop("table", "")
    rpc = params.pop("rpc", "")
    select = params.pop("select", "*")
    filters = params.pop("filters", {})
    limit = params.pop("limit", 100)
    offset = params.pop("offset", 0)
    order = params.pop("order", "")

    if endpoint:
        url = f"{supabase_url}/{endpoint.lstrip('/')}"
    elif rpc:
        url = f"{supabase_url}/rest/v1/rpc/{rpc}"
        method = "POST"
        body = body or params
    elif table:
        url = f"{supabase_url}/rest/v1/{table}"
        query_parts = [f"select={urllib.parse.quote(select)}"]
        for col, val in filters.items():
            query_parts.append(f"{col}=eq.{urllib.parse.quote(str(val))}")
        if order:
            query_parts.append(f"order={urllib.parse.quote(order)}")
        url += "?" + "&".join(query_parts)
    else:
        return {"error": "Missing 'table', 'rpc', or 'endpoint' in params."}

    headers = {
        "apikey": secret.strip(),
        "Authorization": f"Bearer {secret.strip()}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Prefer": "return=representation",
    }

    if method == "GET":
        headers["Range"] = f"{offset}-{offset + limit - 1}"

    data = json.dumps(body).encode("utf-8") if body and method != "GET" else None

    req = urllib.request.Request(url, data=data, method=method, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            response_data = json.loads(resp.read().decode("utf-8"))
            return {
                "status": resp.status,
                "data": response_data,
                "count": len(response_data) if isinstance(response_data, list) else 1,
            }
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")[:1000]
        return {"status": e.code, "error": body_text}
    except (urllib.error.URLError, TimeoutError) as e:
        return {"error": str(e)}
