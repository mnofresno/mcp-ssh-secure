# Security Policy

## Supported Versions

Current branch `main`.

## Reporting a Vulnerability

Open a private security advisory on GitHub.

## Secure Storage

- Do not commit credentials.
- Keep `profiles.json`, key files, and password files outside the repository.
- Recommended permissions:
  - private keys: `0600`
  - password files: `0600`
  - config directory: `0700`

## Threat Model (summary)

- Protect against accidental secret leaks in source control.
- Reduce privilege escalation by requiring explicit sudo confirmation.
- Provide auditable local trail with minimal sensitive content.
- Depend on SSH host key verification (`StrictHostKeyChecking`).
