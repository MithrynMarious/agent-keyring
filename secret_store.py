"""Secret store backends — pluggable vault for the keyring MCP server.

Phase 1: LocalFileStore reads from a local JSON file (gitignored, encrypted at rest by OS).
Phase 2: GCPSecretManagerStore reads from GCP Secret Manager (KEYRING-220 S-01/S-02).

The store returns secret values ONLY to the keyring server internals.
Values MUST NEVER appear in MCP tool results, logs, or conversation context.
"""

import json
import os
import abc
import logging
import re

log = logging.getLogger("keyring.store")


class SecretStore(abc.ABC):
    @abc.abstractmethod
    def get(self, name: str) -> str | None:
        """Return secret value by name, or None if not found."""

    @abc.abstractmethod
    def list_names(self) -> list[str]:
        """Return all secret names (never values)."""

    @abc.abstractmethod
    def exists(self, name: str) -> bool:
        """Check if a secret exists without retrieving its value."""


class LocalFileStore(SecretStore):
    """Reads secrets from a local JSON file. Phase 1 backend.

    File format: {"secret-name": "secret-value", ...}
    The file MUST be gitignored and should live outside the repo.
    """

    def __init__(self, path: str):
        self._path = path
        self._cache: dict[str, str] | None = None

    _PLACEHOLDER_RE = re.compile(r"^<[a-z0-9_-]+:[a-z0-9_-]+>$", re.IGNORECASE)

    def _load(self) -> dict[str, str]:
        if self._cache is not None:
            return self._cache
        if not os.path.exists(self._path):
            log.warning("Secret store file not found: %s", self._path)
            return {}
        with open(self._path, encoding="utf-8") as f:
            raw = json.load(f)
        placeholders = 0
        self._cache = {}
        for k, v in raw.items():
            if k.startswith("_"):
                continue
            if isinstance(v, str) and self._PLACEHOLDER_RE.match(v):
                placeholders += 1
                continue
            self._cache[k] = v
        if placeholders:
            log.warning("Skipped %d placeholder entries — replace them in .secrets.json with real values", placeholders)
        log.info("Loaded %d secrets from local store", len(self._cache))
        return self._cache

    def _resolve(self, raw: str | None) -> str | None:
        """Resolve PASTE_FROM references to actual file content.

        PASTE_FROM paths like '.secrets/file.txt' resolve against
        KEYRING_SECRETS_ROOT (env var), or 3 dirs up from the store file.
        """
        if raw is None or not isinstance(raw, str):
            return raw
        if not raw.startswith("PASTE_FROM:"):
            return raw
        ref_path = raw.split(":", 1)[1].strip()
        if os.path.isabs(ref_path):
            full_path = ref_path
        else:
            root = os.environ.get("KEYRING_SECRETS_ROOT") or os.path.normpath(
                os.path.join(os.path.dirname(self._path), "..", "..", ".."))
            full_path = os.path.normpath(os.path.join(root, ref_path))
        if not os.path.exists(full_path):
            log.warning("PASTE_FROM target not found: %s", full_path)
            return None
        with open(full_path, encoding="utf-8", errors="replace") as f:
            return f.read().strip()

    def get(self, name: str) -> str | None:
        return self._resolve(self._load().get(name))

    def list_names(self) -> list[str]:
        return list(self._load().keys())

    def exists(self, name: str) -> bool:
        return name in self._load()


class GCPSecretManagerStore(SecretStore):
    """Reads secrets from GCP Secret Manager via REST API.

    Auth priority:
      1. Service account JSON key file (GOOGLE_APPLICATION_CREDENTIALS or sa_key_path)
      2. gcloud ADC token file (~/.config/gcloud/application_default_credentials.json)
      3. GCE metadata server (when running on Compute Engine / Cloud Run)

    Zero mandatory dependencies — uses urllib + stdlib JWT. If
    google-cloud-secret-manager is installed, delegates to it instead.

    The optional `prefix` scopes keyring secrets within a shared GCP project:
    a secret named "stripe-api-key" is stored as "{prefix}stripe-api-key" in GCP,
    but the keyring sees it as "stripe-api-key". Default prefix: "keyring-".
    """

    SM_API = "https://secretmanager.googleapis.com/v1"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    SM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
    METADATA_URL = (
        "http://metadata.google.internal/computeMetadata/v1/"
        "instance/service-accounts/default/token"
    )

    def __init__(
        self,
        project_id: str,
        sa_key_path: str | None = None,
        prefix: str = "keyring-",
        cache_ttl: int = 300,
    ):
        self._project = project_id
        self._sa_key_path = sa_key_path or os.environ.get(
            "GOOGLE_APPLICATION_CREDENTIALS"
        )
        self._prefix = prefix
        self._cache_ttl = cache_ttl

        self._token: str | None = None
        self._token_expiry: float = 0
        self._value_cache: dict[str, tuple[str, float]] = {}
        self._names_cache: tuple[list[str], float] | None = None
        self._use_library: bool | None = None

    # --- Library delegation ---

    def _try_library(self):
        """Try google-cloud-secret-manager; fall back to REST."""
        if self._use_library is not None:
            return self._use_library
        try:
            from google.cloud import secretmanager  # noqa: F401
            self._use_library = True
            self._lib_client = secretmanager.SecretManagerServiceClient()
            log.info("GCP Secret Manager: using google-cloud library")
        except ImportError:
            self._use_library = False
            log.info("GCP Secret Manager: using REST API (no library)")
        return self._use_library

    # --- Auth ---

    def _get_access_token(self) -> str:
        import time as _time

        now = _time.time()
        if self._token and now < self._token_expiry - 30:
            return self._token

        if self._sa_key_path:
            self._token, self._token_expiry = self._sa_jwt_exchange()
        else:
            adc_path = self._find_adc()
            if adc_path:
                self._token, self._token_expiry = self._adc_refresh(adc_path)
            else:
                self._token, self._token_expiry = self._metadata_token()

        return self._token

    def _find_adc(self) -> str | None:
        candidates = [
            os.environ.get("CLOUDSDK_CONFIG", ""),
            os.path.join(
                os.environ.get("APPDATA", ""),
                "gcloud",
                "application_default_credentials.json",
            ),
            os.path.expanduser(
                "~/.config/gcloud/application_default_credentials.json"
            ),
        ]
        for p in candidates:
            if p and os.path.isfile(p):
                return p
            # CLOUDSDK_CONFIG points to a dir, not the file
            if p and os.path.isdir(p):
                full = os.path.join(p, "application_default_credentials.json")
                if os.path.isfile(full):
                    return full
        return None

    def _adc_refresh(self, adc_path: str) -> tuple[str, float]:
        """Refresh token from gcloud ADC file."""
        import time as _time
        import urllib.request
        import urllib.parse

        with open(adc_path, encoding="utf-8") as f:
            cred = json.load(f)

        data = urllib.parse.urlencode({
            "client_id": cred["client_id"],
            "client_secret": cred["client_secret"],
            "refresh_token": cred["refresh_token"],
            "grant_type": "refresh_token",
        }).encode("utf-8")

        req = urllib.request.Request(
            self.TOKEN_URL,
            data=data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            tok = json.loads(resp.read().decode("utf-8"))
        return tok["access_token"], _time.time() + tok.get("expires_in", 3600)

    def _sa_jwt_exchange(self) -> tuple[str, float]:
        """Build JWT from service account key, exchange for access token."""
        import base64
        import time as _time

        with open(self._sa_key_path, encoding="utf-8") as f:
            sa = json.load(f)

        now = int(_time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": sa["client_email"],
            "scope": self.SM_SCOPE,
            "aud": self.TOKEN_URL,
            "iat": now,
            "exp": now + 3600,
        }

        def b64url(data: bytes) -> bytes:
            return base64.urlsafe_b64encode(data).rstrip(b"=")

        segments = [
            b64url(json.dumps(header).encode()),
            b64url(json.dumps(claims).encode()),
        ]
        signing_input = b".".join(segments)
        signature = self._rs256_sign(signing_input, sa["private_key"])
        segments.append(b64url(signature))
        jwt_token = b".".join(segments).decode("ascii")

        import urllib.request
        import urllib.parse

        data = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt_token,
        }).encode("utf-8")

        req = urllib.request.Request(
            self.TOKEN_URL,
            data=data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            tok = json.loads(resp.read().decode("utf-8"))
        return tok["access_token"], _time.time() + tok.get("expires_in", 3600)

    @staticmethod
    def _rs256_sign(data: bytes, private_key_pem: str) -> bytes:
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

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", delete=False
        ) as f:
            f.write(private_key_pem)
            key_path = f.name
        try:
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", key_path],
                input=data,
                capture_output=True,
                check=True,
            )
            return result.stdout
        finally:
            os.unlink(key_path)

    def _metadata_token(self) -> tuple[str, float]:
        """Fetch token from GCE metadata server."""
        import time as _time
        import urllib.request

        req = urllib.request.Request(
            self.METADATA_URL,
            headers={"Metadata-Flavor": "Google"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                tok = json.loads(resp.read().decode("utf-8"))
            return (
                tok["access_token"],
                _time.time() + tok.get("expires_in", 3600),
            )
        except Exception as e:
            raise RuntimeError(
                "No GCP credentials found. Set GOOGLE_APPLICATION_CREDENTIALS "
                "to a service account key, or run 'gcloud auth application-default login'."
            ) from e

    # --- REST helpers ---

    def _api_get(self, path: str) -> dict:
        import urllib.request
        import urllib.error

        token = self._get_access_token()
        url = f"{self.SM_API}/{path}"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _api_get_pages(self, path: str) -> list[dict]:
        """Paginated GET — collects all pages."""
        import urllib.request
        import urllib.error
        import urllib.parse

        token = self._get_access_token()
        results: list[dict] = []
        page_token = None

        while True:
            url = f"{self.SM_API}/{path}"
            if page_token:
                sep = "&" if "?" in url else "?"
                url += f"{sep}pageToken={urllib.parse.quote(page_token)}"

            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            results.extend(data.get("secrets", []))
            page_token = data.get("nextPageToken")
            if not page_token:
                break

        return results

    # --- Prefix helpers ---

    def _gcp_name(self, name: str) -> str:
        return f"{self._prefix}{name}"

    def _strip_prefix(self, gcp_name: str) -> str:
        short = gcp_name.rsplit("/", 1)[-1]
        if self._prefix and short.startswith(self._prefix):
            return short[len(self._prefix):]
        return short

    # --- SecretStore interface ---

    def get(self, name: str) -> str | None:
        import time as _time

        cached = self._value_cache.get(name)
        if cached and _time.time() < cached[1]:
            return cached[0]

        gcp_name = self._gcp_name(name)

        if self._try_library():
            return self._get_via_library(name, gcp_name)

        resource = (
            f"projects/{self._project}/secrets/{gcp_name}/versions/latest"
        )
        try:
            data = self._api_get(f"{resource}:access")
            import base64
            payload = base64.b64decode(
                data.get("payload", {}).get("data", "")
            ).decode("utf-8")
            self._value_cache[name] = (payload, _time.time() + self._cache_ttl)
            return payload
        except Exception as e:
            log.error("Failed to access secret %s: %s", name, e)
            return None

    def _get_via_library(self, name: str, gcp_name: str) -> str | None:
        import time as _time

        resource = (
            f"projects/{self._project}/secrets/{gcp_name}/versions/latest"
        )
        try:
            response = self._lib_client.access_secret_version(
                request={"name": resource}
            )
            value = response.payload.data.decode("utf-8")
            self._value_cache[name] = (value, _time.time() + self._cache_ttl)
            return value
        except Exception as e:
            log.error("Failed to access secret %s: %s", name, e)
            return None

    def list_names(self) -> list[str]:
        import time as _time

        if self._names_cache and _time.time() < self._names_cache[1]:
            return self._names_cache[0]

        if self._try_library():
            return self._list_via_library()

        parent = f"projects/{self._project}"
        try:
            filter_str = ""
            if self._prefix:
                filter_str = f"?filter=name:{self._prefix}"
            secrets = self._api_get_pages(f"{parent}/secrets{filter_str}")
            names = [
                self._strip_prefix(s["name"])
                for s in secrets
                if not self._prefix
                or s["name"].rsplit("/", 1)[-1].startswith(self._prefix)
            ]
            self._names_cache = (names, _time.time() + self._cache_ttl)
            return names
        except Exception as e:
            log.error("Failed to list secrets: %s", e)
            return []

    def _list_via_library(self) -> list[str]:
        import time as _time

        parent = f"projects/{self._project}"
        try:
            secrets = self._lib_client.list_secrets(
                request={"parent": parent}
            )
            names = [
                self._strip_prefix(s.name)
                for s in secrets
                if not self._prefix
                or s.name.rsplit("/", 1)[-1].startswith(self._prefix)
            ]
            self._names_cache = (names, _time.time() + self._cache_ttl)
            return names
        except Exception as e:
            log.error("Failed to list secrets: %s", e)
            return []

    def exists(self, name: str) -> bool:
        return name in self.list_names()

    def invalidate_cache(self):
        """Clear all caches — use after secret rotation."""
        self._value_cache.clear()
        self._names_cache = None
        self._token = None
        self._token_expiry = 0
