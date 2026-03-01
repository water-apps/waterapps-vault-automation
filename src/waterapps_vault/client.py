#!/usr/bin/env python3
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


class VaultError(RuntimeError):
    pass


def _normalize_base_url(addr: str) -> str:
    parsed = urllib.parse.urlparse(addr)
    if not parsed.scheme or not parsed.netloc:
        raise VaultError("VAULT_ADDR must be a full URL like https://vault.example.com")
    is_loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and is_loopback):
        raise VaultError("VAULT_ADDR must use https (http is allowed only for localhost)")
    return addr.rstrip("/")


def build_kv_v2_read_url(vault_addr: str, mount: str, path: str) -> str:
    addr = _normalize_base_url(vault_addr)
    mount = mount.strip("/")
    path = path.strip("/")
    return f"{addr}/v1/{mount}/data/{path}"


def build_kv_v2_write_url(vault_addr: str, mount: str, path: str) -> str:
    return build_kv_v2_read_url(vault_addr, mount, path)


def build_jwt_login_url(vault_addr: str, auth_mount: str = "jwt") -> str:
    addr = _normalize_base_url(vault_addr)
    auth_mount = auth_mount.strip("/")
    return f"{addr}/v1/auth/{auth_mount}/login"


def http_json(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body_json: Optional[Dict[str, Any]] = None,
) -> Tuple[int, Dict[str, Any]]:
    data = None
    request_headers = headers.copy() if headers else {}
    if body_json is not None:
        data = json.dumps(body_json).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
            return resp.getcode(), payload
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {"raw": raw}
        raise VaultError(f"HTTP {exc.code} for {url}: {payload}") from exc
    except urllib.error.URLError as exc:
        raise VaultError(f"Connection error for {url}: {exc}") from exc


@dataclass
class VaultClient:
    vault_addr: str
    token: Optional[str] = None
    namespace: Optional[str] = None

    def _headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self.token:
            headers["X-Vault-Token"] = self.token
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        return headers

    def jwt_login(self, role: str, jwt: str, auth_mount: str = "jwt") -> Dict[str, Any]:
        url = build_jwt_login_url(self.vault_addr, auth_mount=auth_mount)
        _, payload = http_json(url, method="POST", headers=self._headers(), body_json={"role": role, "jwt": jwt})
        auth = payload.get("auth") or {}
        client_token = auth.get("client_token")
        if not client_token:
            raise VaultError(f"Vault JWT login response missing auth.client_token: {payload}")
        self.token = client_token
        return payload

    def kv_read(self, mount: str, path: str) -> Dict[str, Any]:
        url = build_kv_v2_read_url(self.vault_addr, mount, path)
        _, payload = http_json(url, method="GET", headers=self._headers())
        data = (((payload.get("data") or {}).get("data")) or {})
        if not isinstance(data, dict):
            raise VaultError(f"Unexpected KV v2 response format: {payload}")
        return data

    def kv_write(self, mount: str, path: str, secret_data: Dict[str, Any]) -> Dict[str, Any]:
        url = build_kv_v2_write_url(self.vault_addr, mount, path)
        _, payload = http_json(url, method="POST", headers=self._headers(), body_json={"data": secret_data})
        return payload


def client_from_env() -> VaultClient:
    addr = os.environ.get("VAULT_ADDR")
    token = os.environ.get("VAULT_TOKEN")
    namespace = os.environ.get("VAULT_NAMESPACE")
    if not addr:
        raise VaultError("VAULT_ADDR is required")
    return VaultClient(vault_addr=addr, token=token, namespace=namespace)
