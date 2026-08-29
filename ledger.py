"""Checkout ledger — append-only JSONL log of secret access.

Every secret checkout is logged: who, what, when, why, which path (DID/AM).
This ledger is the organizational intelligence feedback loop (DC-6, KEYRING-220 S-09):
- Which agents use which services most
- Natural workstation affinity clustering
- Context overload detection (too many key types per agent)
- New-key routing intelligence
"""

import json
import os
import time
import logging
from pathlib import Path

log = logging.getLogger("keyring.ledger")

DEFAULT_LEDGER_PATH = os.path.join(os.path.dirname(__file__), "checkout_ledger.jsonl")


def record_checkout(
    agent_id: str,
    verify_method: str,
    secret_name: str,
    service: str,
    purpose: str | None = None,
    params: dict | None = None,
    ledger_path: str = DEFAULT_LEDGER_PATH,
) -> dict:
    """Append a checkout record to the ledger. Returns the record."""
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "agent_id": agent_id,
        "verify_method": verify_method,
        "secret_name": secret_name,
        "service": service,
        "purpose": purpose,
        "params": _redact_params(params) if params else None,
    }
    entry = {k: v for k, v in entry.items() if v is not None}

    with open(ledger_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")

    log.info("Checkout: %s → %s (%s)", agent_id, secret_name, service)
    return entry


def _redact_params(params: dict) -> dict:
    """Strip anything that looks like a secret value from request params."""
    sensitive_keys = {"key", "token", "secret", "password", "credential", "auth"}
    return {
        k: "***" if any(s in k.lower() for s in sensitive_keys) else v
        for k, v in params.items()
    }


def query_ledger(
    agent_id: str | None = None,
    service: str | None = None,
    secret_name: str | None = None,
    days: int = 30,
    ledger_path: str = DEFAULT_LEDGER_PATH,
) -> list[dict]:
    """Query checkout history with optional filters."""
    if not os.path.exists(ledger_path):
        return []

    cutoff = time.time() - (days * 86400)
    results = []

    with open(ledger_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts_str = entry.get("ts", "")
            try:
                entry_time = time.mktime(time.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ"))
                if entry_time < cutoff:
                    continue
            except (ValueError, OverflowError):
                pass

            if agent_id and entry.get("agent_id") != agent_id:
                continue
            if service and entry.get("service") != service:
                continue
            if secret_name and entry.get("secret_name") != secret_name:
                continue

            results.append(entry)

    return results


def agent_affinity_report(
    days: int = 30,
    ledger_path: str = DEFAULT_LEDGER_PATH,
) -> dict:
    """Compute which agents use which services most — workstation affinity clustering."""
    entries = query_ledger(days=days, ledger_path=ledger_path)

    agent_services: dict[str, dict[str, int]] = {}
    for entry in entries:
        aid = entry.get("agent_id", "unknown")
        svc = entry.get("service", "unknown")
        agent_services.setdefault(aid, {})
        agent_services[aid][svc] = agent_services[aid].get(svc, 0) + 1

    report = {}
    for aid, services in agent_services.items():
        sorted_svcs = sorted(services.items(), key=lambda x: -x[1])
        total = sum(services.values())
        report[aid] = {
            "total_checkouts": total,
            "top_services": sorted_svcs[:5],
            "unique_services": len(services),
        }

    return report
