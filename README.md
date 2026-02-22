# WaterApps Vault Automation

Python CLI and helper library for using HashiCorp Vault (KV v2) in CI/CD, with a focus on GitHub Actions OIDC/JWT auth and secret rotation workflows.

## Purpose

- authenticate GitHub Actions jobs to Vault (JWT/OIDC auth)
- read/write KV v2 secrets for runtime automation
- provide a reusable pattern for WaterApps repos (LinkedIn publisher, deployment pipelines, platform ops)
- ship with tests + CI from day one

## Features

- `jwt-login`: exchange a GitHub OIDC JWT for a Vault token
- `kv-read`: read a KV v2 secret path
- `kv-write`: write/update KV v2 secret fields
- `export-env`: print selected secret fields as shell exports (for local/dev use)
- JSON-first, scriptable CLI output
- no third-party Python dependencies (stdlib only)

## Quick Start

```bash
cd /Users/varunau/Projects/waterapps/instances/water-apps/waterapps-vault-automation
python3 -m unittest discover -s tests -v
python3 -m src.waterapps_vault.cli --help
```

## Example (KV v2 Read)

```bash
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="s.xxxxx"

python3 -m src.waterapps_vault.cli kv-read \
  --mount secret \
  --path waterapps/linkedin-publisher
```

## Example (JWT/OIDC Login for GitHub Actions)

```bash
python3 -m src.waterapps_vault.cli jwt-login \
  --vault-addr "$VAULT_ADDR" \
  --role "github-waterapps-linkedin-publisher" \
  --jwt "$ACTIONS_ID_TOKEN"
```

## Vault Path Convention (recommended)

- KV v2 mount: `secret`
- Secret path: `waterapps/linkedin-publisher`

Stored fields:
- `client_id`
- `client_secret`
- `access_token`
- `refresh_token`
- `author_urn`

## CI/CD

Included GitHub Actions workflow:
- `.github/workflows/python-quality.yml`
  - unit tests
  - basic CLI smoke checks

## Next Integration Targets

1. `waterapps-linkedin-publisher` GitHub Action reads secrets from Vault via OIDC
2. publisher refresh flow writes rotated tokens back to Vault
3. fallback to GitHub secrets only when Vault is unavailable

