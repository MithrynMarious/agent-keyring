"""Agent identity verification — DID primary, AgentMail fallback.

Phase 1: AgentMail verification (GET /inboxes with bearer token confirms inbox ownership).
Phase 2: DID (`did:key`) verification against Embassy registry (EMBASSY2-213 S-15/S-16).

DC-2: DID is primary identity when available; AM is fallback for shipping before Embassy lands.
"""

import json
import os
import logging
from dataclasses import dataclass
from enum import Enum

log = logging.getLogger("keyring.identity")


class VerifyMethod(Enum):
    DID = "did:key"
    AGENTMAIL = "agentmail"
    UNVERIFIED = "unverified"


@dataclass
class AgentIdentity:
    agent_id: str
    method: VerifyMethod
    display_name: str | None = None

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "method": self.method.value,
            "display_name": self.display_name,
        }


def verify_agentmail(bearer_token: str, claimed_inbox: str) -> AgentIdentity | None:
    """Verify agent identity via AgentMail inbox ownership.

    Calls GET /inboxes with the bearer token and checks if the claimed inbox
    appears in the response. If it does, the agent owns that inbox.
    """
    import urllib.request
    import urllib.error

    url = "https://api.agentmail.to/inboxes"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json",
    })

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        log.error("AgentMail verification failed: %s", e)
        return None

    inboxes = data.get("inboxes", data if isinstance(data, list) else [])
    for inbox in inboxes:
        addr = inbox.get("address", inbox.get("email", ""))
        if addr.startswith(claimed_inbox) or claimed_inbox in addr:
            return AgentIdentity(
                agent_id=addr,
                method=VerifyMethod.AGENTMAIL,
                display_name=claimed_inbox.split("@")[0],
            )

    log.warning("Claimed inbox %s not found in AgentMail response", claimed_inbox)
    return None


def verify_did(did_string: str, registry_path: str | None = None) -> AgentIdentity | None:
    """Verify agent identity via DID (`did:key`) against the Embassy registry.

    Phase 2 — requires EMBASSY2-213 S-15/S-16 to land.
    For now, validates format and checks against a local registry file if available.
    """
    if not did_string.startswith("did:key:"):
        log.error("Invalid DID format: %s", did_string)
        return None

    if registry_path and os.path.exists(registry_path):
        with open(registry_path, encoding="utf-8") as f:
            registry = json.load(f)

        entry = registry.get(did_string)
        if entry and not entry.get("revoked", False):
            return AgentIdentity(
                agent_id=did_string,
                method=VerifyMethod.DID,
                display_name=entry.get("name"),
            )
        elif entry and entry.get("revoked"):
            log.warning("DID %s is revoked", did_string)
            return None
        else:
            log.warning("DID %s not found in registry", did_string)
            return None

    # No registry available — format-valid but unregistered
    log.info("DID %s format-valid but no registry to verify against", did_string)
    return AgentIdentity(
        agent_id=did_string,
        method=VerifyMethod.DID,
        display_name=None,
    )


def resolve_identity(
    did: str | None = None,
    agentmail_token: str | None = None,
    agentmail_inbox: str | None = None,
    did_registry_path: str | None = None,
) -> AgentIdentity:
    """Resolve agent identity using available credentials. DID preferred (DC-2)."""
    if did:
        result = verify_did(did, did_registry_path)
        if result:
            return result
        log.warning("DID verification failed, falling back to AgentMail")

    if agentmail_token and agentmail_inbox:
        result = verify_agentmail(agentmail_token, agentmail_inbox)
        if result:
            return result

    return AgentIdentity(
        agent_id="unknown",
        method=VerifyMethod.UNVERIFIED,
    )
