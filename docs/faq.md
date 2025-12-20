# Frequently Asked Questions (FAQ)

> **Quick answers to common questions**

[🏠 Home](../README.md) • [📖 Getting Started](getting-started.md) • [🔧 Troubleshooting](troubleshooting.md)

---

## 📋 Table of Contents

- [General Questions](#general-questions)
- [Setup & Installation](#setup--installation)
- [Authentication & Security](#authentication--security)
- [Configuration](#configuration)
- [Compatibility](#compatibility)
- [Troubleshooting](#troubleshooting)

---

## General Questions

### What is AuthThingie 2?

AuthThingie 2 is a lightweight authentication gateway for self-hosted services. It provides:
- Single sign-on for all your web services
- Support for passkeys, TOTP 2FA, and passwords
- Fine-grained access control via rules
- Easy web-based user management

**Think of it as:** A bouncer for your home server—checks everyone at the door before letting them into any service.

---

### Why should I use AuthThingie 2 instead of Basic Auth?

| Feature | Basic Auth | AuthThingie 2 |
|---------|-----------|--------------|
| Modern login UI | ❌ Browser popup | ✅ Custom page |
| Passkey support | ❌ | ✅ |
| 2FA/TOTP | ❌ | ✅ |
| Centralized users | ❌ | ✅ |
| Session management | ❌ (prompts every time) | ✅ (remember me) |
| Per-service rules | ❌ | ✅ |
| User management UI | ❌ (edit files) | ✅ (web interface) |

---

### How does AuthThingie 2 compare to Authelia or Keycloak?

| Feature | AuthThingie 2 | Authelia | Keycloak |
|---------|--------------|----------|----------|
| **Complexity** | Simple | Medium | High |
| **Resource usage** | Low (~50MB RAM) | Medium (~100-200MB) | High (~500MB+) |
| **Setup time** | 5 minutes | 15-30 minutes | Hours |
| **LDAP/AD integration** | ❌ | ✅ | ✅ |
| **OAuth/OIDC provider** | ❌ | ✅ | ✅ |
| **Passkeys** | ✅ | ✅ | ✅ |
| **Best for** | Home labs, small teams | Medium deployments | Enterprises |

**Bottom line:** If you need OAuth/LDAP, use Authelia or Keycloak. If you want simple SSO for a few services, AuthThingie 2 is perfect.

---

### Is AuthThingie 2 secure?

Yes, when properly configured:
- ✅ **Passwords:** Argon2id hashing (industry standard)
- ✅ **Passkeys:** WebAuthn (phishing-resistant)
- ✅ **Sessions:** Signed, HttpOnly, SameSite cookies
- ✅ **Rate limiting:** Prevents brute force attacks
- ✅ **HTTPS support:** Required for passkeys (use Let's Encrypt)
- ✅ **Open source:** Code is auditable

**Security best practices:**
1. Use HTTPS (required for passkeys anyway)
2. Enable TOTP or passkeys for 2FA
3. Set strong password policies
4. Keep Docker image updated
5. Restrict network access (run behind VPN if public-facing)

---

### Can I use AuthThingie 2 for a business?

**Depends:**
- ✅ **Small business/startup:** Yes, works great
- ✅ **Internal tools only:** Perfect use case
- ⚠️ **Customer-facing auth:** Maybe (lacks OAuth, audit logs)
- ❌ **Enterprise with compliance needs:** No (use Keycloak)

**Licensing:** MIT license allows commercial use.

---

## Setup & Installation

### Do I need Docker?

**Yes.** AuthThingie 2 is distributed as a Docker image.

**No Docker?**
- You can [build from source](advanced.md#building-from-source) and run the binary directly
- You'll need Go 1.25+, SQLite libraries, and manual configuration

---

### What reverse proxy should I use?

**Recommended:** Traefik 2.0+
- Best documented integration
- Dynamic configuration with labels
- Automatic Let's Encrypt certificates

**Also supported:**
- Nginx (requires manual config)
- Caddy (with forward_auth plugin)
- HAProxy (more complex setup)

See [Reverse Proxy Primer](reverse-proxy-primer.md) for details.

---

### Can I use AuthThingie 2 without a reverse proxy?

**No.** Forward authentication requires a reverse proxy to:
1. Intercept requests
2. Check with AuthThingie
3. Forward authenticated requests to services

**The architecture requires it:**
```
User → Reverse Proxy → (auth check with AuthThingie) → Service
```

---

### Do I need a domain name?

**Yes**, for production use:
- Passkeys require a valid domain (IP addresses don't work)
- Cookies are domain-scoped
- HTTPS certificates need a domain

**For testing:**
- You can use `.local` domains with local DNS (e.g., dnsmasq, Pi-hole)
- Or `/etc/hosts` entries: `192.168.1.100 auth.test.local`

---

### Can I use a subdomain for AuthThingie?

**Yes!** In fact, it's recommended:
- ✅ `auth.example.com` (AuthThingie)
- ✅ `sonarr.example.com` (protected service)
- ✅ `radarr.example.com` (protected service)

All share the same root domain (`example.com`) for cookie scope.

---

### How do I migrate from AuthThingie 1?

**Easy!** Built-in migration:

1. Start AuthThingie 2 (no config)
2. Go to setup wizard at `https://auth.example.com`
3. Click **"Import from AuthThingie 1"**
4. Upload your old `auththingie.yaml` file
5. Review imported settings
6. Click **"Complete Import"**

Users, rules, and settings are migrated automatically.

---

## Authentication & Security

### What are passkeys and should I use them?

**Passkeys = Modern, passwordless authentication**

**How they work:**
- Use your device's biometrics (Face ID, Touch ID, fingerprint)
- Private key never leaves your device
- Phishing-resistant (cryptographically bound to domain)

**Should you use them?**
- ✅ **Yes, if possible** - Best security + convenience
- ✅ **Requires HTTPS** - Use Let's Encrypt (free)
- ✅ **Supported devices:** Most phones/laptops from 2018+

**Setup:** Log into AuthThingie → Profile → Security → Add Passkey

---

### Can I use passwords without passkeys?

**Yes.** Passkeys are optional.

**Authentication options (can mix):**
- Password only
- Password + TOTP
- Passkey only
- Passkey + password (fallback)

**Recommended:** At minimum, enable TOTP for admins.

---

### How do I reset a forgotten password?

**Option 1: Via another admin** (if you have another admin account)
1. Log in as admin
2. Go to "Users"
3. Click user → "Reset Password"

**Option 2: Via command line**
```bash
docker exec auththingie /app/auththingie2 user password-reset <username>
# Generates temporary password
```

**Option 3: Direct database edit** (advanced)
```bash
docker exec -it auththingie sqlite3 /config/at2.db
# Manually update password hash (see docs)
```

---

### What happens if I lose my TOTP device?

**Recovery options:**

**Option 1: Use backup codes** (if you saved them during setup)
- Enter backup code instead of TOTP code
- Each code works once

**Option 2: Admin reset**
```bash
docker exec auththingie /app/auththingie2 user disable-totp <username>
```

**Option 3: Database edit** (remove TOTP secret from DB)

**Prevention:** Save backup codes when setting up TOTP!

---

### Can I require 2FA for all users?

**Not enforced automatically**, but you can:
1. Set strong password policy
2. Educate users on enabling TOTP/passkeys
3. Use access rules to restrict sensitive services:
   ```yaml
   rules:
     - name: Admin panel - must have TOTP
       host_pattern: "admin.example.com"
       permitted_users:
         - alice  # Manually verified has 2FA
   ```

**Future feature:** May add "require 2FA" flag per user/role.

---

### How long do sessions last?

**Configurable:**
```yaml
server:
  session_timeout: 24h  # Default
```

**Options:**
- `1h` = 1 hour (high security)
- `24h` = 1 day (balanced)
- `7d` = 1 week (convenience for home lab)

**Trade-off:** Longer = more convenient, shorter = more secure.

---

### Can I force users to re-authenticate?

**Yes, several ways:**

**Method 1: Logout all users**
```bash
# Restart container (clears in-memory sessions)
docker-compose restart auth
```

**Method 2: Change session cookie name**
```yaml
server:
  cookie_name: auththingie_session_v2  # Invalidates old cookies
```

**Method 3: Per-user (future feature)**
Currently not implemented.

---

## Configuration

### Where is the configuration file?

**Inside container:** `/config/auththingie2.yaml`

**On host:** Wherever you mounted `/config` volume

**Example:**
```yaml
volumes:
  - ./config:/config
```
→ Configuration at `./config/auththingie2.yaml`

---

### Can I configure AuthThingie with environment variables?

**Partially.**

**Available env vars:**
- `AT2_CONFIG_PATH` - Config file location
- `AT2_PORT` - Override port
- `AT2_LOG_LEVEL` - Set log level
- `TZ` - Container timezone
- `PUID` / `PGID` - File ownership

**Most settings require YAML config file.**

---

### How do I reload configuration without restarting?

**Rules are hot-reloaded!**
1. Edit `auththingie2.yaml` (change rules)
2. Save file
3. AuthThingie detects change and reloads automatically
4. No restart needed!

**What's NOT hot-reloaded:**
- Server settings (port, domain, etc.) - requires restart
- Database settings - requires restart

---

### Can I use multiple configuration files?

**No.** Single file: `auththingie2.yaml`

**Workaround for large configs:**
- Use YAML anchors for reusable patterns:
  ```yaml
  .admin-users: &admin-users
    - alice
    - bob

  rules:
    - name: Admin panel 1
      permitted_users: *admin-users
    - name: Admin panel 2
      permitted_users: *admin-users
  ```

---

### What's the rule evaluation order?

**First match wins.**

Rules are evaluated **top to bottom** until one matches, then evaluation stops.

**Example:**
```yaml
rules:
  - name: Public blog        # Checked first
    host_pattern: "blog.example.com"
    public: true

  - name: Catch-all auth     # Checked second (only if first didn't match)
    host_pattern: "*.example.com"
```

**Best practice:** Specific rules first, wildcards last.

---

## Compatibility

### Which browsers support passkeys?

**Fully supported:**
- ✅ Chrome/Edge 67+
- ✅ Firefox 60+
- ✅ Safari 13+
- ✅ Mobile browsers (iOS 16+, Android Chrome)

**Not supported:**
- ❌ Internet Explorer
- ❌ Very old browsers (pre-2018)

**Check compatibility:** [WebAuthn browser support](https://caniuse.com/webauthn)

---

### Does AuthThingie 2 work on ARM/Raspberry Pi?

**Yes!** Multi-architecture Docker images available:
- `linux/amd64` (Intel/AMD)
- `linux/arm64` (Raspberry Pi 4, Apple Silicon)
- `linux/arm/v7` (Raspberry Pi 3)

**Pull image:**
```bash
docker pull lthummus/auththingie2:latest
# Automatically selects correct architecture
```

---

### Can I use AuthThingie 2 with Kubernetes?

**Yes**, but not officially documented.

**Considerations:**
- Sessions stored in-memory (won't survive pod restarts)
- No shared session backend (can't scale horizontally)
- Use sticky sessions or accept re-login on pod change

**Better for Kubernetes:** Authelia or Keycloak (designed for distributed deployments)

---

### Does AuthThingie 2 support OAuth/OIDC?

**No.** AuthThingie is not an OAuth provider.

**What this means:**
- ❌ Can't use "Sign in with AuthThingie" on third-party apps
- ❌ No API authentication with bearer tokens
- ✅ Can protect services via forward auth (what it's designed for)

**Need OAuth?** Use Keycloak, Authelia, or Auth0.

---

## Troubleshooting

### Why am I stuck in a redirect loop?

**Most common causes:**

1. **Middleware applied to AuthThingie itself**
   ```yaml
   # WRONG
   auth:
     labels:
       - "traefik.http.routers.auth.middlewares=auththingie@file"  # Remove this!
   ```

2. **Wrong forward auth address**
   ```yaml
   # Must use container name, not domain
   forwardAuth:
     address: "http://auththingie:9000/forward"  # Not https://auth.example.com
   ```

3. **Cookie domain mismatch**
   ```yaml
   # Should be root domain
   server:
     domain: example.com  # Not auth.example.com
   ```

See [Troubleshooting Guide](troubleshooting.md#redirect-loop-problems) for full details.

---

### Service not protected - no login prompt

**Check:**

1. **Middleware applied?**
   ```yaml
   labels:
     - "traefik.http.routers.myservice.middlewares=auththingie@file"
   ```

2. **Traefik loaded dynamic config?**
   ```bash
   docker-compose logs traefik | grep auththingie
   ```

3. **Public rule matching?**
   ```yaml
   rules:
     - host_pattern: "*.example.com"
       public: true  # Too broad!
   ```

---

### Passkey registration fails

**Requirements:**
- ✅ HTTPS enabled (not HTTP)
- ✅ Valid TLS certificate (not self-signed)
- ✅ Supported browser/device
- ✅ Domain in config matches URL

**Check:**
```yaml
server:
  auth_url: https://auth.example.com  # Must match browser URL exactly
```

**Quick test:** If URL bar shows "Not Secure" or self-signed warning, passkeys won't work.

---

### How do I enable debug logging?

**In `auththingie2.yaml`:**
```yaml
server:
  log_level: debug
```

**Restart:**
```bash
docker-compose restart auth
```

**View logs:**
```bash
docker-compose logs -f auth
```

**Remember:** Set back to `info` when done (debug is very verbose).

---

### Where can I get more help?

1. **Check documentation:**
   - [Getting Started](getting-started.md)
   - [Troubleshooting Guide](troubleshooting.md)
   - [Configuration Reference](configuration.md)

2. **Search GitHub issues:** [Existing reports](https://github.com/lthummus/auththingie2/issues)

3. **Open new issue:** Include logs, config (sanitized), and steps to reproduce

---

## 🔗 Related Documentation

- **[Getting Started](getting-started.md)** - Setup from scratch
- **[Troubleshooting](troubleshooting.md)** - Detailed problem-solving
- **[Configuration Reference](configuration.md)** - All config options
- **[Architecture](architecture.md)** - How it works

---

[🏠 Back to Home](../README.md)
