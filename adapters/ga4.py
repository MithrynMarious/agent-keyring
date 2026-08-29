"""GA4 Data API adapter for Agent Keyring.

EPIC-KEYRING-220 S-05. Supports two credential types:
  1. OAuth client secrets JSON (refresh token flow)
  2. Service account key JSON (JWT flow)

The secret value is either a JSON string (OAuth or SA key) or a plain
access token. The adapter auto-detects which and builds the auth header.

GA4 Data API docs: https://developers.google.com/analytics/devguides/reporting/data/v1
Endpoint: https://analyticsdata.googleapis.com/v1beta/properties/{propertyId}:runReport
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

GA4_API_BASE = "https://analyticsdata.googleapis.com/v1beta"
OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
GA4_SCOPE = "https://www.googleapis.com/auth/analytics.readonly"


def ga4_adapter(
    secret: str,
    method: str = "POST",
    endpoint: str = "",
    params: dict | None = None,
    body: dict | None = None,
) -> dict:
    """GA4 Data API adapter.

    The `params` dict carries GA4-specific fields:
      property_id: GA4 property ID (e.g. "123456789" or "properties/123456789")
      metrics:     list of metric names (e.g. ["sessions", "activeUsers"])
      dimensions:  list of dimension names (e.g. ["date", "country"])
      date_range:  {"start": "2026-01-01", "end": "2026-01-31"} or "last7days"
      limit:       max rows (default 10000)
      offset:      pagination offset

    If `body` is provided directly, it's sent as-is to the Data API (advanced).
    If `endpoint` is provided, it overrides the default :runReport path.
    """
    params = params or {}

    try:
        access_token = _resolve_access_token(secret)
    except Exception as e:
        return {"error": f"Auth failed: {type(e).__name__}: {e}"}

    property_id = params.get("property_id", params.get("property", ""))
    if not property_id and not endpoint:
        return {"error": "Missing property_id in params."}

    if property_id and not property_id.startswith("properties/"):
        property_id = f"properties/{property_id}"

    if body is None:
        body = _build_report_request(params)

    if endpoint:
        url = f"{GA4_API_BASE}/{endpoint.lstrip('/')}"
    else:
        url = f"{GA4_API_BASE}/{property_id}:runReport"

    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            response_data = json.loads(resp.read().decode("utf-8"))
            return {
                "status": resp.status,
                "data": _format_report(response_data),
                "raw_row_count": response_data.get("rowCount", 0),
            }
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")[:1000]
        return {"status": e.code, "error": body_text}
    except (urllib.error.URLError, TimeoutError) as e:
        return {"error": str(e)}


def _resolve_access_token(secret: str) -> str:
    """Auto-detect credential type and return a usable access token."""
    try:
        cred = json.loads(secret)
    except (json.JSONDecodeError, TypeError):
        # plain token string
        return secret.strip()

    if cred.get("type") == "service_account":
        return _sa_token(cred)

    if "installed" in cred or "web" in cred:
        return _oauth_refresh_token(cred)

    if "client_id" in cred and "refresh_token" in cred:
        return _oauth_refresh_token(cred)

    raise ValueError(
        "Unrecognized credential format. Expected: service account JSON, "
        "OAuth client secrets JSON with refresh_token, or a plain access token."
    )


def _oauth_refresh_token(cred: dict) -> str:
    """Exchange an OAuth refresh token for a fresh access token."""
    inner = cred.get("installed") or cred.get("web") or cred
    client_id = inner.get("client_id", "")
    client_secret = inner.get("client_secret", "")
    refresh_token = cred.get("refresh_token") or inner.get("refresh_token", "")

    if not all([client_id, client_secret, refresh_token]):
        raise ValueError(
            "OAuth credential missing client_id, client_secret, or refresh_token. "
            "Run the OAuth consent flow first to obtain a refresh token."
        )

    data = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }).encode("utf-8")

    req = urllib.request.Request(
        OAUTH_TOKEN_URL,
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        token_data = json.loads(resp.read().decode("utf-8"))
        return token_data["access_token"]


def _sa_token(cred: dict) -> str:
    """Build a JWT from a service account key and exchange for an access token.

    Uses only stdlib — no google-auth dependency. The JWT is RS256-signed
    using the SA's private key via the `cryptography` package (available
    in most Python environments) or falls back to shelling out to openssl.
    """
    import base64
    import hashlib
    import struct

    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {
        "iss": cred["client_email"],
        "scope": GA4_SCOPE,
        "aud": OAUTH_TOKEN_URL,
        "iat": now,
        "exp": now + 3600,
    }

    segments = [
        _b64url(json.dumps(header).encode()),
        _b64url(json.dumps(claims).encode()),
    ]
    signing_input = b".".join(segments)

    signature = _rs256_sign(signing_input, cred["private_key"])
    segments.append(_b64url(signature))
    jwt = b".".join(segments).decode("ascii")

    data = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": jwt,
    }).encode("utf-8")

    req = urllib.request.Request(
        OAUTH_TOKEN_URL,
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        token_data = json.loads(resp.read().decode("utf-8"))
        return token_data["access_token"]


def _b64url(data: bytes) -> bytes:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _rs256_sign(data: bytes, private_key_pem: str) -> bytes:
    """RS256 signature. Tries cryptography lib, then openssl subprocess."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None
        )
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    except ImportError:
        pass

    import subprocess
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
        f.write(private_key_pem)
        key_path = f.name
    try:
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", key_path],
            input=data, capture_output=True, check=True,
        )
        return result.stdout
    finally:
        os.unlink(key_path)


def _build_report_request(params: dict) -> dict:
    """Build a GA4 Data API runReport request body from simplified params."""
    req = {}

    metrics = params.get("metrics", [])
    if isinstance(metrics, str):
        metrics = [m.strip() for m in metrics.split(",")]
    if metrics:
        req["metrics"] = [{"name": m} for m in metrics]

    dimensions = params.get("dimensions", [])
    if isinstance(dimensions, str):
        dimensions = [d.strip() for d in dimensions.split(",")]
    if dimensions:
        req["dimensions"] = [{"name": d} for d in dimensions]

    date_range = params.get("date_range", params.get("dateRange"))
    if isinstance(date_range, str):
        presets = {
            "today": (0, 0), "yesterday": (1, 1),
            "last7days": (6, 0), "last28days": (27, 0),
            "last30days": (29, 0), "last90days": (89, 0),
        }
        key = date_range.lower().replace(" ", "").replace("_", "")
        if key in presets:
            from datetime import date, timedelta
            end = date.today() - timedelta(days=presets[key][1])
            start = date.today() - timedelta(days=presets[key][0])
            req["dateRanges"] = [{"startDate": start.isoformat(), "endDate": end.isoformat()}]
        else:
            req["dateRanges"] = [{"startDate": date_range, "endDate": date_range}]
    elif isinstance(date_range, dict):
        req["dateRanges"] = [{
            "startDate": date_range.get("start", date_range.get("startDate", "")),
            "endDate": date_range.get("end", date_range.get("endDate", "")),
        }]

    if not req.get("dateRanges"):
        from datetime import date, timedelta
        end = date.today()
        start = end - timedelta(days=29)
        req["dateRanges"] = [{"startDate": start.isoformat(), "endDate": end.isoformat()}]

    limit = params.get("limit", 10000)
    req["limit"] = str(limit)

    offset = params.get("offset")
    if offset:
        req["offset"] = str(offset)

    return req


def _format_report(raw: dict) -> dict:
    """Reshape GA4 runReport response into a cleaner agent-friendly format."""
    dim_headers = [h.get("name", "") for h in raw.get("dimensionHeaders", [])]
    met_headers = [h.get("name", "") for h in raw.get("metricHeaders", [])]

    rows = []
    for row in raw.get("rows", []):
        entry = {}
        for i, dv in enumerate(row.get("dimensionValues", [])):
            if i < len(dim_headers):
                entry[dim_headers[i]] = dv.get("value", "")
        for i, mv in enumerate(row.get("metricValues", [])):
            if i < len(met_headers):
                entry[met_headers[i]] = mv.get("value", "")
        rows.append(entry)

    totals = {}
    for total_row in raw.get("totals", []):
        for i, mv in enumerate(total_row.get("metricValues", [])):
            if i < len(met_headers):
                totals[met_headers[i]] = mv.get("value", "")

    return {
        "dimensions": dim_headers,
        "metrics": met_headers,
        "rows": rows,
        "row_count": raw.get("rowCount", len(rows)),
        "totals": totals,
    }
