"""Tests for secret_store.py — LocalFileStore backend."""

import json
import os

import pytest

from secret_store import LocalFileStore


class TestLocalFileStore:
    def test_load_and_list(self, tmp_secrets_file):
        store = LocalFileStore(tmp_secrets_file)
        names = store.list_names()
        assert "test-api-key" in names
        assert "test-token" in names
        assert len(names) == 3

    def test_get_plain_secret(self, tmp_secrets_file):
        store = LocalFileStore(tmp_secrets_file)
        val = store.get("test-api-key")
        assert val == "sk-test-12345"

    def test_get_nonexistent_returns_none(self, tmp_secrets_file):
        store = LocalFileStore(tmp_secrets_file)
        assert store.get("nonexistent-key") is None

    def test_exists(self, tmp_secrets_file):
        store = LocalFileStore(tmp_secrets_file)
        assert store.exists("test-api-key") is True
        assert store.exists("nonexistent") is False

    def test_paste_from_resolution(self, tmp_secrets_file, tmp_path):
        os.environ["KEYRING_SECRETS_ROOT"] = str(tmp_path)
        try:
            store = LocalFileStore(tmp_secrets_file)
            val = store.get("paste-ref")
            assert val == "resolved-paste-value"
        finally:
            del os.environ["KEYRING_SECRETS_ROOT"]

    def test_paste_from_missing_file_returns_none(self, tmp_path):
        secrets = {"broken-ref": "PASTE_FROM:.secrets/missing.txt"}
        path = tmp_path / ".secrets.json"
        path.write_text(json.dumps(secrets), encoding="utf-8")
        os.environ["KEYRING_SECRETS_ROOT"] = str(tmp_path)
        try:
            store = LocalFileStore(str(path))
            assert store.get("broken-ref") is None
        finally:
            del os.environ["KEYRING_SECRETS_ROOT"]

    def test_missing_store_file_returns_empty(self, tmp_path):
        store = LocalFileStore(str(tmp_path / "nonexistent.json"))
        assert store.list_names() == []
        assert store.get("anything") is None

    def test_cache_consistency(self, tmp_secrets_file):
        store = LocalFileStore(tmp_secrets_file)
        first = store.list_names()
        second = store.list_names()
        assert first == second
