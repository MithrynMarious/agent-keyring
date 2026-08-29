"""Shared fixtures for Agent Keyring tests."""

import json
import os
import tempfile

import pytest


@pytest.fixture
def tmp_secrets_file(tmp_path):
    """Create a temporary secrets JSON file with test data."""
    secrets = {
        "test-api-key": "sk-test-12345",
        "test-token": "tok_abc_def",
        "paste-ref": "PASTE_FROM:.secrets/test-paste.txt",
    }
    path = tmp_path / ".secrets.json"
    path.write_text(json.dumps(secrets), encoding="utf-8")

    paste_dir = tmp_path / ".secrets"
    paste_dir.mkdir()
    (paste_dir / "test-paste.txt").write_text("resolved-paste-value", encoding="utf-8")

    return str(path)


@pytest.fixture
def tmp_permissions_file(tmp_path):
    """Create a temporary permissions JSON file."""
    perms = {
        "allowed-agent@agentmail.to": ["test-api-key", "test-token"],
        "wildcard-agent@agentmail.to": ["*"],
        "empty-agent@agentmail.to": [],
        "_default": [],
    }
    path = tmp_path / "permissions.json"
    path.write_text(json.dumps(perms), encoding="utf-8")
    return str(path)


@pytest.fixture
def tmp_manifest_file(tmp_path):
    """Create a temporary secret manifest."""
    manifest = {
        "secrets": [
            {
                "name": "test-api-key",
                "service": "test",
                "description": "Test API key",
                "status": "active",
            },
            {
                "name": "cataloged-key",
                "service": "other",
                "description": "Cataloged only",
                "status": "cataloged",
            },
        ]
    }
    path = tmp_path / "secret_manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return str(path)
