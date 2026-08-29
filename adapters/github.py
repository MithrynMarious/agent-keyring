"""GitHub API adapter for Agent Keyring.

Supports: repos, issues, PRs, user info, search.
The secret is a GitHub personal access token (ghp_... or github_pat_...).
"""

import json
import urllib.error
import urllib.parse
import urllib.request

GITHUB_API_BASE = "https://api.github.com"


def github_adapter(
    secret: str,
    method: str = "GET",
    endpoint: str = "",
    params: dict | None = None,
    body: dict | None = None,
) -> dict:
    """GitHub REST API adapter.

    The `params` dict carries:
      action:    'repos', 'issues', 'pulls', 'user', 'search', 'actions'
      owner:     Repository owner (e.g. 'MithrynMarious')
      repo:      Repository name
      number:    Issue or PR number
      state:     Filter state ('open', 'closed', 'all')
      per_page:  Results per page (default 30, max 100)
      page:      Page number
      query:     Search query string (for 'search' action)
      search_type: 'repositories', 'issues', 'code' (for 'search' action)
    """
    params = params or {}

    action = params.pop("action", "") or endpoint.strip("/")
    owner = params.pop("owner", "")
    repo = params.pop("repo", "")
    number = params.pop("number", None)
    query = params.pop("query", "")
    search_type = params.pop("search_type", "repositories")

    if action == "user":
        url = f"{GITHUB_API_BASE}/user"
    elif action == "search":
        if not query:
            return {"error": "Missing 'query' for search action."}
        url = f"{GITHUB_API_BASE}/search/{search_type}?q={urllib.parse.quote(query)}"
    elif action in ("repos", "issues", "pulls", "actions"):
        if not owner or not repo:
            return {"error": f"Missing 'owner' and 'repo' for '{action}' action."}
        if action == "repos":
            url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
        elif number:
            resource = "issues" if action == "issues" else "pulls"
            url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/{resource}/{number}"
        else:
            resource = action
            url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/{resource}"
    elif endpoint:
        url = f"{GITHUB_API_BASE}/{endpoint.lstrip('/')}"
    else:
        return {"error": "Missing 'action' or 'endpoint'. Supported: repos, issues, pulls, user, search."}

    query_params = {}
    for k in ("state", "per_page", "page", "sort", "direction"):
        if k in params:
            query_params[k] = params.pop(k)

    if query_params:
        sep = "&" if "?" in url else "?"
        url += sep + urllib.parse.urlencode(query_params)

    headers = {
        "Authorization": f"Bearer {secret.strip()}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    data = json.dumps(body).encode("utf-8") if body and method != "GET" else None
    if data:
        headers["Content-Type"] = "application/json"

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
