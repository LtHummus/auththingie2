# Troubleshooting Guide

> **Fix common issues and debug AuthThingie 2**

[🏠 Home](../README.md) • [📖 Getting Started](getting-started.md) • [❓ FAQ](faq.md)

---

## 📋 Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Cannot Access AuthThingie](#cannot-access-auththingie)
- [Login Issues](#login-issues)
- [Redirect Loop Problems](#redirect-loop-problems)
- [Services Not Protected](#services-not-protected)
- [Passkey Issues](#passkey-issues)
- [Configuration Errors](#configuration-errors)
- [Performance Issues](#performance-issues)
- [Getting Help](#getting-help)

---

## Quick Diagnostics

Before diving into specific issues, run these checks:

### 1. Check Container Status

```bash
docker ps | grep auththingie
```

**Expected:** Container should be "Up" status
**If not running:** See [Cannot Access AuthThingie](#cannot-access-auththingie)

---

### 2. View Logs

```bash
docker-compose logs auth
# Or for live logs
docker-compose logs -f auth
```

Look for:
- ✅ `Server listening on port 9000`
- ❌ Error messages with stack traces
- ⚠️ Warning about config issues

---

### 3. Verify Traefik Can Reach AuthThingie

```bash
# From inside Traefik container
docker exec traefik wget -O- http://auththingie:9000/health
```

**Expected:** `{"status":"ok"}` or similar
**If fails:** Network connectivity issue (see below)

---

### 4. Check Configuration

```bash
# View current config
cat ~/docker/auththingie2/config/auththingie2.yaml

# Check for YAML syntax errors
docker run --rm -v $(pwd)/config:/config mikefarah/yq eval /config/auththingie2.yaml
```

---

## Cannot Access AuthThingie

### Symptom
`auth.example.com` shows "502 Bad Gateway" or times out.

---

### Cause 1: Container Not Running

**Check:**
```bash
docker ps -a | grep auth
```

**If status is "Exited":**
```bash
# View why it exited
docker-compose logs auth

# Common causes:
# - Config file syntax error
# - Port already in use
# - Volume mount permission issue
```

**Fix:**
```bash
# Fix the underlying issue, then
docker-compose up -d auth
```

---

### Cause 2: Port Mismatch

**Check:** Traefik label port matches AuthThingie listening port

**Docker Compose:**
```yaml
# This should be 9000 (or whatever AuthThingie uses)
- "traefik.http.services.auth.loadbalancer.server.port=9000"
```

**AuthThingie Config:**
```yaml
server:
  port: 9000  # Must match above
```

**Fix:** Change one to match the other, then restart.

---

### Cause 3: Network Isolation

**Check:** Both containers on same Docker network

```bash
docker network inspect bridge | grep -A 5 "auththingie\|traefik"
```

**Fix:** Ensure same network in `docker-compose.yml`:
```yaml
services:
  traefik:
    networks:
      - web

  auth:
    networks:
      - web  # Must match Traefik's network

networks:
  web:
    external: true
```

---

### Cause 4: DNS Not Resolving

**Check:**
```bash
# From your machine
nslookup auth.example.com
```

**Fix:**
- Verify DNS record points to your server's IP
- Check router/Pi-hole configuration
- Try accessing by IP: `http://192.168.1.100:9000`

---

## Login Issues

### Symptom
Login page loads but can't log in.

---

### Cause 1: Incorrect Credentials

**Check:** Username and password are correct (case-sensitive)

**Reset password via command line:**
```bash
# Reset admin password
docker exec auththingie /app/auththingie2 user password-reset admin
```

---

### Cause 2: Account Locked

**Check logs:**
```bash
docker-compose logs auth | grep -i "locked\|too many"
```

**Fix:** Wait for lockout duration to expire, or reset:
```bash
docker exec auththingie /app/auththingie2 user unlock <username>
```

---

### Cause 3: Database Corruption

**Symptoms:**
- Login fails with "internal server error"
- Logs show database errors

**Fix:**
```bash
# Backup current database
cp config/at2.db config/at2.db.backup

# Check database integrity
docker exec auththingie sqlite3 /config/at2.db "PRAGMA integrity_check;"

# If corrupted, restore from backup or start fresh
mv config/at2.db config/at2.db.corrupted
# Restart container to create new database
docker-compose restart auth
```

---

### Cause 4: Session Cookie Issues

**Check:** Cookies are being set correctly

**In browser DevTools (F12):**
1. Open "Application" or "Storage" tab
2. Check "Cookies" → `auth.example.com`
3. Should see `auththingie_session` or similar

**If missing:**
- Check `domain` setting matches your root domain
- Ensure using HTTPS (cookies may not set over HTTP)
- Try different browser (rule out extension interference)

**Fix:**
```yaml
# In auththingie2.yaml
server:
  domain: example.com  # Should be ROOT domain, not subdomain
```

---

## Redirect Loop Problems

### Symptom
Browser keeps redirecting between service and login page endlessly.

```
sonarr.example.com → auth.example.com → sonarr.example.com → ...
```

---

### Cause 1: Middleware Applied to AuthThingie

**Don't do this:**
```yaml
# WRONG - AuthThingie itself shouldn't be protected
services:
  auth:
    labels:
      - "traefik.http.routers.auth.middlewares=auththingie@file"  # ❌ Remove this!
```

**Fix:** Remove middleware from AuthThingie's router.

---

### Cause 2: Wrong Forward Auth Address

**Check Traefik config:**
```yaml
http:
  middlewares:
    auththingie:
      forwardAuth:
        address: "http://auththingie:9000/forward"  # Must be /forward endpoint
```

**Common mistakes:**
- ❌ `http://auththingie:9000/auth` (wrong path)
- ❌ `http://auth.example.com:9000/forward` (should use container name)
- ❌ `http://auththingie:9000` (missing /forward)

---

### Cause 3: Misconfigured `auth_url`

**Check:**
```yaml
# In auththingie2.yaml
server:
  auth_url: https://auth.example.com  # Must match actual URL
```

**If wrong, AuthThingie redirects to incorrect URL → loop**

**Fix:** Update to correct URL and restart.

---

### Cause 4: Cookie Domain Mismatch

**Problem:** Cookie set for wrong domain

**Example:**
- AuthThingie at: `auth.example.com`
- Cookie domain: `.different-domain.com`
- Cookie won't be sent to `example.com` services

**Fix:**
```yaml
server:
  domain: example.com  # Should match all your services
```

---

## Services Not Protected

### Symptom
Can access service without logging in.

---

### Cause 1: Middleware Not Applied

**Check service labels:**
```yaml
services:
  sonarr:
    labels:
      - "traefik.http.routers.sonarr.middlewares=auththingie@file"  # Missing?
```

**Fix:** Add the middleware label, then:
```bash
docker-compose up -d sonarr
```

---

### Cause 2: Public Rule Matches

**Check rules in `auththingie2.yaml`:**
```yaml
rules:
  - name: Too broad public rule
    host_pattern: "*.example.com"  # Matches everything!
    public: true
```

**Fix:** Make rules more specific or reorder them (specific rules first).

---

### Cause 3: Traefik Not Loading Dynamic Config

**Check Traefik logs:**
```bash
docker-compose logs traefik | grep -i "auththingie\|middleware"
```

**Look for:**
- ✅ `Configuration loaded from file: auththingie.yml`
- ❌ `Error loading configuration`

**Fix:**
```bash
# Ensure file is in correct location
ls /path/to/traefik/dynamic/auththingie.yml

# Restart Traefik to reload
docker-compose restart traefik
```

---

### Cause 4: Wrong Middleware Reference

**Middleware name must match:**

**In Traefik dynamic config:**
```yaml
http:
  middlewares:
    auththingie:  # This name
```

**In service labels:**
```yaml
- "traefik.http.routers.sonarr.middlewares=auththingie@file"  # Must match
```

---

## Passkey Issues

### Symptom
Passkey registration fails or doesn't show up.

---

### Cause 1: HTTPS Not Enabled

**Passkeys require HTTPS.** Period.

**Check:**
```bash
# Visit your site - URL should show https://
# Certificate must be valid (not self-signed)
```

**Fix:**
- Set up Let's Encrypt in Traefik
- Ensure `tls=true` in router labels
- Self-signed certificates don't work for WebAuthn

---

### Cause 2: Wrong Domain in Config

**WebAuthn is domain-bound.**

**Check:**
```yaml
server:
  auth_url: https://auth.example.com  # Must match browser URL exactly
```

**If you access via IP or different domain, passkeys won't work.**

---

### Cause 3: Browser Compatibility

**Check:** [WebAuthn browser support](https://caniuse.com/webauthn)

**Supported:**
- ✅ Chrome 67+
- ✅ Firefox 60+
- ✅ Safari 13+
- ✅ Edge 18+

**Not supported:**
- ❌ IE 11
- ❌ Very old mobile browsers

---

### Cause 4: No Authenticator Available

**User needs one of:**
- Touch ID / Face ID (Mac/iPhone/iPad)
- Windows Hello (Windows 10+)
- Android fingerprint/face unlock
- Physical security key (YubiKey, etc.)

**Check:** "Sign in with passkey" shows device-specific prompt.

---

## Configuration Errors

### Symptom
AuthThingie won't start or shows config errors in logs.

---

### YAML Syntax Error

**Logs show:**
```
Error parsing config: yaml: line 12: found character that cannot start any token
```

**Common mistakes:**
- Missing quotes around strings with special chars
- Inconsistent indentation (use spaces, not tabs)
- Missing colons after keys

**Fix:**
```bash
# Validate YAML syntax
docker run --rm -v $(pwd)/config:/config mikefarah/yq eval /config/auththingie2.yaml

# Or use the online validator: [YAML Lint](https://www.yamllint.com/)
```

---

### Invalid Duration Format

**Wrong:**
```yaml
server:
  session_timeout: 24hours  # ❌ No space
```

**Correct:**
```yaml
server:
  session_timeout: 24h  # ✅ Valid duration
```

**Valid units:** `s`, `m`, `h`, `d` (no spaces)

---

### Database File Not Writable

**Logs show:**
```
Error opening database: unable to open database file: readonly
```

**Fix:**
```bash
# Check directory permissions
ls -la config/

# Ensure container user can write
chmod 755 config/
chown 1000:1000 config/  # Or your PUID/PGID
```

---

## Performance Issues

### Symptom
Slow logins or service access.

---

### Large Rule Set

**Problem:** Evaluating 100+ rules on every request

**Fix:**
- Put most common rules first
- Use specific patterns instead of wildcards
- Combine rules where possible

---

### Database on Network Storage

**Problem:** SQLite on NFS/CIFS is slow and can corrupt

**Fix:**
```yaml
volumes:
  - ./config/auththingie2.yaml:/config/auththingie2.yaml  # Config on network storage is OK
  - auth-db:/config/at2.db  # Database on local volume

volumes:
  auth-db:
    driver: local
```

---

### Memory Constraints

**Check:**
```bash
docker stats auththingie
```

**If memory usage high:**
- Check for session leaks (restart container)
- Reduce `session_timeout` to expire old sessions faster

---

## Getting Help

### Gather Information

Before opening an issue, collect:

1. **Docker Compose config** (sanitized)
2. **AuthThingie config** (remove sensitive data)
3. **Logs** (last 50 lines)
   ```bash
   docker-compose logs --tail=50 auth > auth-logs.txt
   ```
4. **Traefik dynamic config** for middleware
5. **Versions:**
   ```bash
   docker inspect lthummus/auththingie2 | grep -A 3 "Labels"
   ```

---

### Enable Debug Logging

**In `auththingie2.yaml`:**
```yaml
server:
  log_level: debug  # Very verbose!
```

**Restart:**
```bash
docker-compose restart auth
```

**View debug logs:**
```bash
docker-compose logs -f auth
```

⚠️ **Remember to set back to `info` when done** (debug logs can get huge!)

---

### Check GitHub Issues

Search existing issues: [GitHub issue tracker](https://github.com/lthummus/auththingie2/issues)

**Common searches:**
- "redirect loop"
- "passkey"
- "502 bad gateway"
- "session"

---

### Open a New Issue

If your problem isn't covered:

1. Use a descriptive title: ❌ "It doesn't work" ✅ "Login redirect loop with multiple domains"
2. Include versions (AuthThingie, Traefik, Docker)
3. Provide minimal reproduction steps
4. Attach sanitized configs and logs
5. Describe expected vs. actual behavior

**Open issue here:** [Create a new GitHub issue](https://github.com/lthummus/auththingie2/issues/new)

---

## 🔗 Related Documentation

- **[FAQ](faq.md)** - Common questions
- **[Configuration Reference](configuration.md)** - All config options
- **[Getting Started](getting-started.md)** - Setup from scratch
- **[Architecture](architecture.md)** - How it works

---

[🏠 Back to Home](../README.md)
