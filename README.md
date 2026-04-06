# certs

A CLI tool for generating and rotating ES384 key pairs for JWT issuers. Private keys are stored in 1Password; public keys are written to local JWKS files.

## Prerequisites

- [1Password CLI (`op`)](https://developer.1password.com/docs/cli/) installed and signed in
- Go 1.26+

## Installation

```sh
go install github.com/thiago/certs/src@latest
```

Or build from source:

```sh
go build -o certs ./src
```

## Configuration

Create an `issuers.yaml` file (the default config path):

```yaml
vault: "Private"

issuers:
  - name: "my-service"
    algorithm: "ES384"
  - name: "another-service"
    algorithm: "ES384"
    op_vault: "Work"   # override the global vault for this issuer
```

**Fields:**

| Field | Description |
|-------|-------------|
| `vault` | Default 1Password vault name |
| `issuers[].name` | Issuer name (lowercase alphanumeric + hyphens) |
| `issuers[].algorithm` | Key algorithm — only `ES384` is supported |
| `issuers[].op_vault` | (optional) Per-issuer 1Password vault override |

## Usage

```sh
certs <command> [flags]
```

**Commands:**

| Command | Description |
|---------|-------------|
| `generate` | Generate new key pairs for issuers |
| `rotate` | Rotate keys (appends new key, keeps previous keys in JWKS) |
| `list` | List keys in local JWKS files |

**Flags (all commands):**

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `issuers.yaml` | Path to config file |
| `--issuer` | _(all)_ | Target a single issuer by name |

**Examples:**

```sh
# Generate keys for all issuers
certs generate

# Generate keys for a single issuer using a custom config
certs generate --config prod.yaml --issuer my-service

# Rotate keys for all issuers
certs rotate

# List keys in local JWKS files
certs list
```

## How it works

1. **`generate`** — Creates a new ES384 key pair. Stores the private key in 1Password as `<issuer>/<kid>`, then appends the public key to `./<issuer>.jwks.json`.
2. **`rotate`** — Same as generate, but requires that a JWKS file already exists. The new public key is appended, keeping old keys for graceful rollover.
3. **`list`** — Reads each issuer's local JWKS file and prints key metadata (kid, algorithm, curve, use).

Private keys are stored in 1Password under the item name `<issuer>/<kid>` in the configured vault. JWKS files are written to the current directory as `<issuer>.jwks.json`.
