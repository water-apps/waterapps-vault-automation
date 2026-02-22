# Vault + GitHub Actions OIDC Setup (Design Notes)

## Goal

Allow GitHub Actions to authenticate to Vault using OIDC/JWT and read/write secrets without storing long-lived Vault tokens in GitHub.

## Recommended Flow

1. GitHub Actions requests an OIDC token (`id-token: write` permission)
2. Workflow exchanges JWT with Vault auth mount (`auth/jwt/login`)
3. Workflow reads/writes KV v2 secret path (`secret/data/waterapps/...`)
4. Downstream steps consume secrets via env vars

## Example Secret Path (KV v2)

- Mount: `secret`
- Path: `waterapps/linkedin-publisher`

## Required Vault Components

- JWT/OIDC auth method enabled (for GitHub Actions)
- Vault role mapped to GitHub repo/workflow claims
- KV v2 secrets engine mounted (e.g., `secret/`)
- Policy allowing:
  - read/write `secret/data/waterapps/linkedin-publisher`
  - read metadata if needed (`secret/metadata/...`)

## Example Policy (conceptual)

```hcl
path "secret/data/waterapps/linkedin-publisher" {
  capabilities = ["read", "update"]
}
```

## Notes

- HCP Vault may require `VAULT_NAMESPACE`
- Keep `client_secret` and refresh tokens in Vault, not GitHub, once migration is complete
- Add repository-specific roles for least privilege

