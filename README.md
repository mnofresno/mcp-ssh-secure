# mcp-ssh-secure

Go-based MCP server for secure, generic, and auditable SSH execution without storing credentials in the repository.

## Goals

- Support generic SSH connection modes (`key`, `agent`, `password`).
- Handle passphrase-protected SSH keys with interactive `ssh-add` flows.
- Require explicit confirmation before running `sudo` commands.
- Keep local audit logs without exposing secrets.
- Keep credentials out of source control.

## MCP Tools

- `list_profiles`
- `ensure_ssh_agent_key`
- `run_ssh_command`
- `run_sudo_command`
- `audit_tail`

`profile` is optional for execution tools and is resolved by alias/default matching.

## Security Design

- Credentials live in `~/.config/mcp-ssh-secure/profiles.json` and/or referenced local files.
- The repository includes only `profiles.example.json`.
- Local audit file is `~/.local/state/mcp-ssh-secure/audit.log` with `0600` permissions.
- `run_sudo_command` requires `confirm="YES"`.
- If an SSH key is passphrase-protected, `ensure_ssh_agent_key` returns a controlled error so the LLM asks the user for the passphrase.
- After OS restart, `ssh-agent` state is lost by design; run `ensure_ssh_agent_key` again.

## Quick Install

```bash
git clone https://github.com/mnofresno/mcp-ssh-secure.git
cd mcp-ssh-secure
go build -o bin/mcp-ssh-secure ./cmd/mcp-ssh-secure
mkdir -p ~/.config/mcp-ssh-secure
cp profiles.example.json ~/.config/mcp-ssh-secure/profiles.json
```

## Environment-specific Install (personal_europlanet)

This repository includes an environment bootstrap script:

```bash
bash scripts/install-local-personal-europlanet.sh
```

That script:

- creates `~/.config/mcp-ssh-secure/profiles.json` using local credential files
- sets `sudo_password_file` from a local secure file
- builds the binary at `~/mcp-ssh-secure/bin/mcp-ssh-secure`
- registers the server as the 8th MCP server in `~/.codex/config.toml`
- configures relaxed production aliases (`prod`, `production`, `production server`, etc.)

## Passphrase Flow

1. LLM calls `ensure_ssh_agent_key` with `{}` or a relaxed hint like `{ "profile": "prod" }`.
2. If passphrase is required, the server returns a message requesting it.
3. LLM asks the user for the passphrase.
4. LLM calls `ensure_ssh_agent_key` again with `passphrase`.
5. `ssh-add` stores the key in `ssh-agent` for the current OS session.

## Testing

```bash
go test ./...
```

## Audit

Local file:

- `~/.local/state/mcp-ssh-secure/audit.log`

Query from MCP:

- `audit_tail`

## Limitations

- `password` mode requires `sshpass`.
- This server delegates to system binaries `ssh`, `ssh-add`, and `ssh-keygen`.
