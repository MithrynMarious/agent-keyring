"""Tests for adapter contracts — every adapter follows the same interface.

These are structural/contract tests, not integration tests. They verify:
1. Every adapter has the correct function signature
2. Every adapter returns the expected dict shape on error
3. No adapter leaks the secret value in its return data
"""

import inspect

import pytest

from adapters.stripe import stripe_adapter
from adapters.supabase import supabase_adapter
from adapters.anthropic import anthropic_adapter
from adapters.github import github_adapter
from adapters.discord import discord_adapter
from adapters.ga4 import ga4_adapter


ALL_ADAPTERS = [
    ("stripe", stripe_adapter),
    ("supabase", supabase_adapter),
    ("anthropic", anthropic_adapter),
    ("github", github_adapter),
    ("discord", discord_adapter),
    ("ga4", ga4_adapter),
]

FAKE_SECRET = "sk-test-NEVER-LEAK-THIS-VALUE-12345"


class TestAdapterSignatures:
    @pytest.mark.parametrize("name,adapter", ALL_ADAPTERS)
    def test_signature_matches_contract(self, name, adapter):
        sig = inspect.signature(adapter)
        param_names = list(sig.parameters.keys())
        assert "secret" in param_names, f"{name} adapter missing 'secret' parameter"
        assert "method" in param_names, f"{name} adapter missing 'method' parameter"
        assert "endpoint" in param_names, f"{name} adapter missing 'endpoint' parameter"
        assert "params" in param_names, f"{name} adapter missing 'params' parameter"
        assert "body" in param_names, f"{name} adapter missing 'body' parameter"

    @pytest.mark.parametrize("name,adapter", ALL_ADAPTERS)
    def test_returns_dict(self, name, adapter):
        result = adapter(secret=FAKE_SECRET)
        assert isinstance(result, dict), f"{name} adapter must return a dict"


class TestAdapterErrorHandling:
    def test_stripe_missing_resource(self):
        result = stripe_adapter(secret=FAKE_SECRET, params={})
        assert "error" in result

    def test_supabase_missing_url(self):
        result = supabase_adapter(secret=FAKE_SECRET, params={})
        assert "error" in result

    def test_github_missing_action(self):
        result = github_adapter(secret=FAKE_SECRET, params={})
        assert "error" in result

    def test_discord_missing_action(self):
        result = discord_adapter(secret=FAKE_SECRET, params={})
        assert "error" in result


class TestDC1SecretLeakage:
    """DC-1 compliance: adapter return values must never contain the secret.

    This is the resident failing case for secret leakage. If any adapter
    starts including the secret in its return data, this test catches it.
    """

    @pytest.mark.parametrize("name,adapter", ALL_ADAPTERS)
    def test_secret_not_in_return_value(self, name, adapter):
        result = adapter(secret=FAKE_SECRET)
        result_str = str(result)
        assert FAKE_SECRET not in result_str, (
            f"DC-1 VIOLATION: {name} adapter leaked the secret value in its return data"
        )

    @pytest.mark.parametrize("name,adapter", ALL_ADAPTERS)
    def test_error_response_no_secret(self, name, adapter):
        result = adapter(secret=FAKE_SECRET, endpoint="/nonexistent")
        result_str = str(result)
        assert FAKE_SECRET not in result_str, (
            f"DC-1 VIOLATION: {name} adapter leaked secret in error response"
        )
