#!/usr/bin/env python3
import argparse
import json
import os
import sys
from typing import Dict

from .client import VaultError, VaultClient, client_from_env


def parse_kv_pairs(pairs: list[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in pairs:
        if "=" not in item:
            raise ValueError(f"Expected key=value pair, got: {item}")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"Empty key in pair: {item}")
        out[key] = value
    return out


def cmd_jwt_login(args: argparse.Namespace) -> int:
    jwt = args.jwt or os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN") or os.environ.get("VAULT_JWT")
    if not jwt:
        print("[ERROR] JWT is required (--jwt or VAULT_JWT)", file=sys.stderr)
        return 1
    client = VaultClient(vault_addr=args.vault_addr or os.environ.get("VAULT_ADDR", ""), namespace=args.namespace or os.environ.get("VAULT_NAMESPACE"))
    if not client.vault_addr:
        print("[ERROR] VAULT_ADDR is required (--vault-addr or env)", file=sys.stderr)
        return 1
    payload = client.jwt_login(role=args.role, jwt=jwt, auth_mount=args.auth_mount)
    print(json.dumps({"vault_token_obtained": True, "lease_duration": ((payload.get("auth") or {}).get("lease_duration"))}, indent=2))
    if args.export_env:
        print(f'export VAULT_TOKEN="{client.token}"')
    return 0


def cmd_kv_read(args: argparse.Namespace) -> int:
    client = client_from_env()
    data = client.kv_read(args.mount, args.path)
    if args.field:
        if args.field not in data:
            print(f"[ERROR] Field not found: {args.field}", file=sys.stderr)
            return 1
        print(data[args.field])
        return 0
    print(json.dumps(data, indent=2))
    return 0


def cmd_kv_write(args: argparse.Namespace) -> int:
    client = client_from_env()
    data = parse_kv_pairs(args.set or [])
    if not data:
        print("[ERROR] At least one --set key=value is required", file=sys.stderr)
        return 1
    payload = client.kv_write(args.mount, args.path, data)
    print(json.dumps({"ok": True, "vault_response": payload}, indent=2))
    return 0


def cmd_export_env(args: argparse.Namespace) -> int:
    client = client_from_env()
    data = client.kv_read(args.mount, args.path)
    keys = args.fields or sorted(data.keys())
    for key in keys:
        if key not in data:
            print(f"[WARN] Field not found, skipping: {key}", file=sys.stderr)
            continue
        env_name = args.prefix + key.upper()
        value = str(data[key]).replace('"', '\\"')
        print(f'export {env_name}="{value}"')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="WaterApps Vault Automation CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_jwt = sub.add_parser("jwt-login", help="Exchange a JWT (e.g., GitHub OIDC token) for a Vault token")
    p_jwt.add_argument("--vault-addr")
    p_jwt.add_argument("--namespace")
    p_jwt.add_argument("--auth-mount", default="jwt")
    p_jwt.add_argument("--role", required=True)
    p_jwt.add_argument("--jwt", help="OIDC/JWT token value (or set VAULT_JWT)")
    p_jwt.add_argument("--export-env", action="store_true", help="Print export VAULT_TOKEN=... after login")
    p_jwt.set_defaults(func=cmd_jwt_login)

    p_read = sub.add_parser("kv-read", help="Read a Vault KV v2 secret")
    p_read.add_argument("--mount", default="secret")
    p_read.add_argument("--path", required=True)
    p_read.add_argument("--field", help="Print a single field only")
    p_read.set_defaults(func=cmd_kv_read)

    p_write = sub.add_parser("kv-write", help="Write Vault KV v2 secret fields")
    p_write.add_argument("--mount", default="secret")
    p_write.add_argument("--path", required=True)
    p_write.add_argument("--set", action="append", help="key=value (repeatable)")
    p_write.set_defaults(func=cmd_kv_write)

    p_export = sub.add_parser("export-env", help="Read a secret and print shell exports")
    p_export.add_argument("--mount", default="secret")
    p_export.add_argument("--path", required=True)
    p_export.add_argument("--fields", nargs="*", help="Subset of fields to export")
    p_export.add_argument("--prefix", default="", help="Env var prefix (example: LINKEDIN_)")
    p_export.set_defaults(func=cmd_export_env)

    args = parser.parse_args()
    try:
        return args.func(args)
    except VaultError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

