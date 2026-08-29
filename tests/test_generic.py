"""Tests for the generic REST adapter and service registry."""

import json

import pytest

from adapters.generic import (
    SERVICE_REGISTRY,
    generic_adapter,
    make_adapter,
    AUTH_BEARER,
    AUTH_HEADER,
    AUTH_BASIC,
    AUTH_QUERY,
)


class TestServiceRegistry:
    def test_registry_has_services(self):
        assert len(SERVICE_REGISTRY) >= 20

    def test_all_entries_have_required_fields(self):
        for name, config in SERVICE_REGISTRY.items():
            assert "base_url" in config, f"{name} missing base_url"
            assert "auth" in config, f"{name} missing auth"
            assert config["auth"] in (AUTH_BEARER, AUTH_HEADER, AUTH_BASIC, AUTH_QUERY), (
                f"{name} has invalid auth type: {config['auth']}"
            )

    def test_header_auth_has_header_name(self):
        for name, config in SERVICE_REGISTRY.items():
            if config["auth"] == AUTH_HEADER:
                assert "auth_header" in config, f"{name} uses header auth but missing auth_header"

    def test_query_auth_has_param_name(self):
        for name, config in SERVICE_REGISTRY.items():
            if config["auth"] == AUTH_QUERY:
                assert "auth_param" in config or "url_template" in config, (
                    f"{name} uses query auth but missing auth_param or url_template"
                )


class TestMakeAdapter:
    def test_creates_callable(self):
        adapter = make_adapter("slack")
        assert callable(adapter)

    def test_returns_none_for_unknown(self):
        assert make_adapter("nonexistent-service") is None

    def test_all_registered_services_create_adapters(self):
        for name in SERVICE_REGISTRY:
            adapter = make_adapter(name)
            assert adapter is not None, f"make_adapter({name!r}) returned None"
            assert callable(adapter)


class TestGenericAdapter:
    def test_missing_base_url_returns_error(self):
        result = generic_adapter("secret", service_config={})
        assert "error" in result

    def test_dc1_secret_not_in_error(self):
        secret = "sk-super-secret-test-key-12345"
        result = generic_adapter(secret, service_config={"base_url": "", "auth": "bearer"})
        result_str = json.dumps(result)
        assert secret not in result_str
