"""Tests for permission checking logic."""

import json
import os
import sys

import pytest


def _check_permission_with_file(perms_path: str, agent_id: str, secret_name: str) -> bool:
    """Standalone permission check matching server.py logic."""
    with open(perms_path, encoding="utf-8") as f:
        perms = json.load(f)
    allowed = perms.get(agent_id, perms.get("_default", []))
    return "*" in allowed or secret_name in allowed


class TestPermissions:
    def test_allowed_agent_allowed_secret(self, tmp_permissions_file):
        assert _check_permission_with_file(
            tmp_permissions_file, "allowed-agent@agentmail.to", "test-api-key"
        ) is True

    def test_allowed_agent_disallowed_secret(self, tmp_permissions_file):
        assert _check_permission_with_file(
            tmp_permissions_file, "allowed-agent@agentmail.to", "other-secret"
        ) is False

    def test_wildcard_agent_any_secret(self, tmp_permissions_file):
        assert _check_permission_with_file(
            tmp_permissions_file, "wildcard-agent@agentmail.to", "any-secret-name"
        ) is True

    def test_empty_agent_denied(self, tmp_permissions_file):
        assert _check_permission_with_file(
            tmp_permissions_file, "empty-agent@agentmail.to", "test-api-key"
        ) is False

    def test_unknown_agent_uses_default(self, tmp_permissions_file):
        assert _check_permission_with_file(
            tmp_permissions_file, "unknown@agentmail.to", "test-api-key"
        ) is False

    def test_default_deny_when_empty(self, tmp_permissions_file):
        assert _check_permission_with_file(
            tmp_permissions_file, "stranger@agentmail.to", "test-api-key"
        ) is False

    def test_dc1_default_deny_is_structural(self, tmp_path):
        """DC-1 resident failing case: verify default-deny is the structural default."""
        perms = {"specific-agent@agentmail.to": ["one-secret"]}
        path = tmp_path / "permissions.json"
        path.write_text(json.dumps(perms), encoding="utf-8")
        assert _check_permission_with_file(
            str(path), "other-agent@agentmail.to", "one-secret"
        ) is False
