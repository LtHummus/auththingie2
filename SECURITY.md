# Security Policy

## Supported Versions

Only the latest, published release of AuthThingie2 is officially supported. There is no LTS system. Patch releases are cut directly from `main` automatically.

## Reporting a Vulnerability

Please report suspected security issues using [GitHub's private vulnerability reporting](https://github.com/LtHummus/auththingie2/security/advisories/new) rather than a public issue. This is especially important for any authentication or authorization bypass.

Things in scope:

- Bypasses of rule-based path/host authorization matching
- Bypasses of trusted-proxy / client-IP detection
- Authentication bypass (including passwords, WebAuthN/passkeys, TOTP)
- Credential handling issues (hashing issues, secrets, session tokens)
- Open redirects on login/logout

Not in scope:

- Vulnerabilities that require some sort of weird, insecure deployment configuration (misconfigured proxy, trusted-proxy setups intentionally loosened by the server owner)

## Response

This is a personally maintained project. I will acknowledge reports on a best-effort basis, I am just a single person, so I don't have any sort of SLA guarantee.

