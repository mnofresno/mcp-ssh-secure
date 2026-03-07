# mcp-ssh-secure

Servidor MCP en Go para ejecutar SSH de forma segura, genérica y auditable, sin guardar credenciales en el repositorio.

## Objetivos

- Soportar conexiones SSH genéricas (`key`, `agent`, `password`).
- Manejar keys con passphrase en forma interactiva con `ssh-add`.
- Exigir confirmación explícita antes de ejecutar comandos con `sudo`.
- Guardar auditoría local sin secretos.
- Mantener credenciales fuera de Git.

## Herramientas MCP

- `list_profiles`
- `ensure_ssh_agent_key`
- `run_ssh_command`
- `run_sudo_command`
- `audit_tail`

`profile` es opcional en las herramientas de ejecución y se resuelve por alias/default.

## Diseño de seguridad

- Las credenciales viven en `~/.config/mcp-ssh-secure/profiles.json` y/o en archivos locales referenciados.
- El repo incluye solo `profiles.example.json`.
- Auditoría local en `~/.local/state/mcp-ssh-secure/audit.log` con permisos `0600`.
- `run_sudo_command` requiere `confirm="YES"`.
- Si la key SSH tiene passphrase, `ensure_ssh_agent_key` responde error controlado para que el LLM pida passphrase al usuario.
- En cada reinicio de la computadora se pierde el estado del `ssh-agent`, por diseño se requiere volver a ejecutar `ensure_ssh_agent_key`.

## Instalación rápida

```bash
git clone https://github.com/mnofresno/mcp-ssh-secure.git
cd mcp-ssh-secure
go build -o bin/mcp-ssh-secure ./cmd/mcp-ssh-secure
mkdir -p ~/.config/mcp-ssh-secure
cp profiles.example.json ~/.config/mcp-ssh-secure/profiles.json
```

## Instalación específica (personal_europlanet)

Este repo incluye un script para tu entorno:

```bash
bash scripts/install-local-personal-europlanet.sh
```

Ese script:

- crea `~/.config/mcp-ssh-secure/profiles.json` apuntando a `$HOME/digital_ocean/vps-digital-ocean`
- configura `sudo_password_file` hacia `$HOME/digital_ocean/.sudo_password_temp`
- compila binario en `~/mcp-ssh-secure/bin/mcp-ssh-secure`
- agrega el servidor MCP como 8º servidor en `~/.codex/config.toml`
- configura alias laxos para producción (`prod`, `production`, `server de prod`, etc.)

## Flujo con keys con passphrase

1. LLM llama `ensure_ssh_agent_key` con `{}` o con un hint laxo como `{ "profile": "prod" }`.
2. Si falta passphrase, el servidor devuelve mensaje pidiendo passphrase.
3. LLM le pide passphrase al usuario.
4. LLM llama `ensure_ssh_agent_key` con passphrase.
5. `ssh-add` guarda la key en `ssh-agent` para la sesión actual del OS.

## Testing

```bash
go test ./...
```

## Auditoría

Archivo local:

- `~/.local/state/mcp-ssh-secure/audit.log`

Consulta desde MCP:

- `audit_tail`

## Limitaciones

- El modo `password` requiere `sshpass` instalado.
- Este servidor delega en binarios `ssh`, `ssh-add`, `ssh-keygen` del sistema.
