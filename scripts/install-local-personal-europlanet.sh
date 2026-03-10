#!/usr/bin/env bash
set -euo pipefail

HOME_DIR="${HOME}"
PROJECT_DIR="${HOME_DIR}/mcp-ssh-secure"
CONFIG_DIR="${HOME_DIR}/.config/mcp-ssh-secure"
CONFIG_FILE="${CONFIG_DIR}/profiles.json"
CODEX_CONFIG="${HOME_DIR}/.codex/config.toml"
KEY_PATH="${HOME_DIR}/digital_ocean/vps-digital-ocean"
SUDO_PATH="${HOME_DIR}/digital_ocean/.sudo_password_temp"
KNOWN_HOSTS_PATH="${HOME_DIR}/.ssh/known_hosts"

if [[ ! -f "${KEY_PATH}" ]]; then
  echo "Missing key file: ${KEY_PATH}" >&2
  exit 1
fi
if [[ ! -f "${SUDO_PATH}" ]]; then
  echo "Missing sudo password file: ${SUDO_PATH}" >&2
  exit 1
fi

mkdir -p "${CONFIG_DIR}"
chmod 700 "${CONFIG_DIR}"

cat > "${CONFIG_FILE}" <<JSON
{
  "profiles": {
    "personal_europlanet": {
      "host": "77.42.43.120",
      "port": 2222,
      "user": "mariano-fresno",
      "key_path": "${KEY_PATH}",
      "known_hosts_path": "${KNOWN_HOSTS_PATH}",
      "strict_host_key_checking": true,
      "force_ipv4": true,
      "connect_timeout_sec": 15,
      "sudo_password_file": "${SUDO_PATH}",
      "auth_mode": "agent",
      "aliases": [
        "prod",
        "production",
        "production server",
        "my production server",
        "live",
        "main server"
      ],
      "default": true
    }
  },
  "audit": {
    "log_path": "${HOME_DIR}/.local/state/mcp-ssh-secure/audit.log"
  }
}
JSON

chmod 600 "${CONFIG_FILE}"
chmod 600 "${KEY_PATH}" || true
chmod 600 "${SUDO_PATH}" || true

cd "${PROJECT_DIR}"
go build -o bin/mcp-ssh-secure ./cmd/mcp-ssh-secure

if ! rg -n "\[mcp_servers\.ssh_secure\]" "${CODEX_CONFIG}" >/dev/null 2>&1; then
  cat >> "${CODEX_CONFIG}" <<'TOML'

[mcp_servers.ssh_secure]
command = "/Users/mariano.fresno/mcp-ssh-secure/bin/mcp-ssh-secure"
env = { MCP_SSH_SECURE_CONFIG = "/Users/mariano.fresno/.config/mcp-ssh-secure/profiles.json" }
TOML
fi

echo "Installed mcp-ssh-secure locally."
