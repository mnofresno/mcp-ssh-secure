# Audit Notes

## What is logged

Each action logs:

- timestamp
- action
- profile
- status
- redacted detail

## What is not logged

- private key contents
- passphrases
- sudo passwords
- full raw command outputs when not necessary

## File location

`~/.local/state/mcp-ssh-secure/audit.log`
