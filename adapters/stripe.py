"""Stripe API adapter for Agent Keyring.

Supports: charges, customers, subscriptions, balance, invoices.
Read-only by default — uses GET for all standard operations.
The secret is a Stripe API key (sk_live_... or sk_test_...).
"""

import json
import urllib.error
import urllib.parse
import urllib.request
import base64

STRIPE_API_BASE = "https://api.stripe.com/v1"


def stripe_adapter(
    secret: str,
    method: str = "GET",
    endpoint: str = "",
    params: dict | None = None,
    body: dict | None = None,
) -> dict:
    """Stripe REST API adapter.

    The `params` dict carries Stripe-specific fields:
      resource:  'charges', 'customers', 'subscriptions', 'balance',
                 'invoices', 'payouts', 'products', 'prices'
      id:        specific resource ID (e.g. 'ch_xxx', 'cus_xxx')
      limit:     max results (default 10, max 100)
      starting_after: pagination cursor
      Any other keys are passed as query params to Stripe.
    """
    params = params or {}

    resource = params.pop("resource", "") or endpoint.strip("/")
    if not resource:
        return {"error": "Missing 'resource' in params (e.g. 'charges', 'customers', 'balance')."}

    resource_id = params.pop("id", None)

    url = f"{STRIPE_API_BASE}/{resource}"
    if resource_id:
        url = f"{url}/{resource_id}"

    if method == "GET" and params:
        url += "?" + urllib.parse.urlencode(params)

    auth_b64 = base64.b64encode(f"{secret.strip()}:".encode()).decode()

    data = None
    if body and method in ("POST", "PUT", "PATCH"):
        data = urllib.parse.urlencode(_flatten(body)).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Basic {auth_b64}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            response_data = json.loads(resp.read().decode("utf-8"))
            return {"status": resp.status, "data": response_data}
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")[:1000]
        return {"status": e.code, "error": body_text}
    except (urllib.error.URLError, TimeoutError) as e:
        return {"error": str(e)}


def _flatten(d: dict, parent_key: str = "") -> list[tuple[str, str]]:
    """Flatten nested dicts for Stripe's form-encoded API."""
    items = []
    for k, v in d.items():
        key = f"{parent_key}[{k}]" if parent_key else k
        if isinstance(v, dict):
            items.extend(_flatten(v, key))
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    items.extend(_flatten(item, f"{key}[{i}]"))
                else:
                    items.append((f"{key}[{i}]", str(item)))
        else:
            items.append((key, str(v)))
    return items
