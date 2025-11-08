# Advanced Usage Guide

> **Complex scenarios, optimization, and development**

[🏠 Home](../README.md) • [📖 Getting Started](getting-started.md) • [⚙️ Configuration](configuration.md)

---

## 📋 Table of Contents

- [Multiple Domains](#multiple-domains)
- [IP Whitelisting](#ip-whitelisting)
- [Role-Based Access Control](#role-based-access-control)
- [High Availability Setup](#high-availability-setup)
- [Integration with Other Tools](#integration-with-other-tools)
- [Reverse Proxy Alternatives](#reverse-proxy-alternatives)
- [Performance Optimization](#performance-optimization)
- [Development](#development)
- [Building from Source](#building-from-source)

---

## Multiple Domains

### Scenario
You want to use AuthThingie across different root domains (e.g., `personal.com` and `work.com`).

### Challenge
Session cookies are domain-scoped. A cookie for `personal.com` won't work on `work.com`.

### Solution 1: Separate AuthThingie Instances

Run two independent AuthThingie containers, one per domain.

**Docker Compose:**
```yaml
services:
  auth-personal:
    container_name: auth-personal
    image: lthummus/auththingie2
    volumes:
      - ./config-personal:/config
    labels:
      - "traefik.http.services.auth-personal.loadbalancer.server.port=9000"
      - "traefik.http.routers.auth-personal.rule=Host(`auth.personal.com`)"

  auth-work:
    container_name: auth-work
    image: lthummus/auththingie2
    volumes:
      - ./config-work:/config
    labels:
      - "traefik.http.services.auth-work.loadbalancer.server.port=9000"
      - "traefik.http.routers.auth-work.rule=Host(`auth.work.com`)"
```

**Traefik Middleware:**
```yaml
http:
  middlewares:
    auth-personal:
      forwardAuth:
        address: "http://auth-personal:9000/forward"

    auth-work:
      forwardAuth:
        address: "http://auth-work:9000/forward"
```

**Apply to services:**
```yaml
services:
  blog:  # Uses personal domain
    labels:
      - "traefik.http.routers.blog.rule=Host(`blog.personal.com`)"
      - "traefik.http.routers.blog.middlewares=auth-personal@file"

  wiki:  # Uses work domain
    labels:
      - "traefik.http.routers.wiki.rule=Host(`wiki.work.com`)"
      - "traefik.http.routers.wiki.middlewares=auth-work@file"
```

**Pros:**
- ✅ Separate user databases per domain
- ✅ Different security policies
- ✅ Isolated failures

**Cons:**
- ❌ Users need accounts on both
- ❌ More containers to manage

---

### Solution 2: Subdomain Strategy

Use subdomains under one root domain: `personal.example.com`, `work.example.com`

**Single AuthThingie instance at `auth.example.com` works for both!**

```yaml
server:
  domain: example.com  # Works for all subdomains
```

---

## IP Whitelisting

### Scenario 1: Local Network Bypass

Allow direct access from home network without authentication.

```yaml
rules:
  - name: Home network - no auth needed
    source_ip: "192.168.1.0/24"
    public: true

  - name: Everything else requires auth
    host_pattern: "*.example.com"
```

**Effect:**
- From home: Direct access ✅
- From internet: Must log in 🔐

---

### Scenario 2: VPN-Only Access

Require VPN connection for certain services.

```yaml
rules:
  - name: Admin panel - VPN only
    host_pattern: "admin.example.com"
    source_ip: "10.8.0.0/24"  # WireGuard VPN subnet
    permitted_roles:
      - admin

  - name: Regular services - any authenticated user
    host_pattern: "*.example.com"
```

**Effect:**
- Admin panel: Must be on VPN + have admin role
- Other services: Just need authentication

---

### Scenario 3: Office Hours Restriction

Combine with external tools for time-based access.

**Use Traefik's IPWhiteList middleware:**
```yaml
# In Traefik dynamic config
http:
  middlewares:
    office-hours:
      plugin:
        SchedulerMiddleware:
          allowedHours: "09:00-17:00"
          timezone: "America/New_York"

  routers:
    admin:
      middlewares:
        - auththingie@file
        - office-hours
```

---

## Role-Based Access Control

### Creating Roles

Roles exist in the database and are assigned via the web UI.

**Common role structure:**
```
admin       → Full access to everything
developer   → Access to dev/staging environments
viewer      → Read-only services
customer    → Public-facing customer portal
```

---

### Hierarchical Access Example

```yaml
rules:
  # Admin portal - admins only
  - name: Admin panel
    host_pattern: "admin.example.com"
    permitted_roles:
      - admin

  # Development tools - admins and devs
  - name: GitLab
    host_pattern: "gitlab.example.com"
    permitted_roles:
      - admin
      - developer

  # Monitoring - admins, devs, and viewers
  - name: Grafana
    host_pattern: "grafana.example.com"
    permitted_roles:
      - admin
      - developer
      - viewer

  # Customer portal - customers only
  - name: Customer app
    host_pattern: "app.example.com"
    permitted_roles:
      - customer

  # Everything else - authenticated users
  - name: Default
    host_pattern: "*.example.com"
```

---

### Dynamic Role Assignment

**Via Web UI:**
1. Log into AuthThingie
2. Go to "Users"
3. Click user → "Edit"
4. Add/remove roles
5. Changes take effect immediately (no restart)

**Via API (future feature):**
```bash
curl -X POST https://auth.example.com/api/users/alice/roles \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"role": "developer"}'
```

---

## High Availability Setup

### Challenge
Single AuthThingie instance = single point of failure.

### Solution 1: Container Restart Policies

**Automatic restart on failure:**
```yaml
services:
  auth:
    restart: unless-stopped  # Always restart unless manually stopped
```

**This handles:**
- ✅ Crashes
- ✅ Server reboots
- ❌ Does NOT handle host failure

---

### Solution 2: Health Checks

**Monitor and restart unhealthy containers:**
```yaml
services:
  auth:
    image: lthummus/auththingie2
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:9000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    restart: unless-stopped
```

---

### Solution 3: Multiple Instances (Limited)

⚠️ **Current limitation:** Sessions are in-memory, not shared.

**What this means:**
- Can't run multiple AuthThingie instances sharing session state
- Load balancer would break sessions (user A on instance 1, next request → instance 2 → not logged in)

**Workaround:**
Use Traefik's sticky sessions:
```yaml
http:
  services:
    auth:
      loadBalancer:
        sticky:
          cookie:
            name: auth_instance
```

**Better solution:** Wait for future version with Redis session backend.

---

## Integration with Other Tools

### Fail2Ban

Block IPs with too many failed logins.

**Monitor AuthThingie logs:**
```bash
# /etc/fail2ban/filter.d/auththingie.conf
[Definition]
failregex = ^.*Failed login attempt for user .* from <HOST>$
ignoreregex =
```

**Jail config:**
```bash
# /etc/fail2ban/jail.d/auththingie.conf
[auththingie]
enabled = true
port = http,https
logpath = /var/log/docker/auththingie.log
maxretry = 5
bantime = 3600
```

---

### Prometheus Monitoring

**Enable metrics in config:**
```yaml
server:
  metrics_enabled: true
```

**Scrape configuration:**
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'auththingie'
    static_configs:
      - targets: ['auththingie:9000']
    metrics_path: /metrics
```

**Available metrics:**
- `auththingie_login_attempts_total{result="success|failure"}`
- `auththingie_active_sessions`
- `auththingie_forward_auth_duration_seconds`
- `auththingie_http_requests_total{method,path,status}`

---

### Grafana Dashboard

**Import dashboard JSON (create your own or wait for community contributions)**

**Key panels:**
- Login success/failure rate
- Active sessions over time
- Top users by request count
- Failed login attempts by IP
- Response time percentiles

---

## Reverse Proxy Alternatives

While Traefik is recommended, AuthThingie works with other proxies supporting forward auth.

### Nginx

**Configuration:**
```nginx
server {
    listen 443 ssl;
    server_name sonarr.example.com;

    location / {
        # Forward auth check
        auth_request /auth;
        auth_request_set $user $upstream_http_x_forwarded_user;

        proxy_pass http://sonarr:8989;
        proxy_set_header X-Forwarded-User $user;
    }

    location = /auth {
        internal;
        proxy_pass http://auththingie:9000/forward;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
    }
}
```

**Redirect to login on 401:**
```nginx
error_page 401 = @error401;

location @error401 {
    return 302 https://auth.example.com/login?redirect=$scheme://$http_host$request_uri;
}
```

---

### Caddy

**Caddyfile:**
```caddy
sonarr.example.com {
    forward_auth auththingie:9000 {
        uri /forward
        copy_headers X-Forwarded-User
    }

    reverse_proxy sonarr:8989
}

auth.example.com {
    reverse_proxy auththingie:9000
}
```

**Install forward_auth plugin:**
```bash
caddy add-package github.com/kirsch33/realip
```

---

### HAProxy

**Configuration:**
```haproxy
frontend https_front
    bind *:443 ssl crt /etc/ssl/certs/example.com.pem
    acl auth_ok http_auth(auththingie)

    http-request deny if !auth_ok
    use_backend sonarr if { hdr(host) -i sonarr.example.com }

backend auththingie
    http-request lua.auth_check

backend sonarr
    server sonarr1 sonarr:8989
```

**Lua script for forward auth (more complex, see HAProxy docs)**

---

## Performance Optimization

### 1. Optimize Rules

**Bad (evaluates all rules every time):**
```yaml
rules:
  - name: Rule 1
    host_pattern: "app1.example.com"
    path_pattern: "/api/*"
  - name: Rule 2
    host_pattern: "app1.example.com"
    path_pattern: "/admin/*"
  # ... 50 more rules
```

**Good (stops at first match):**
```yaml
rules:
  # Most common requests first
  - name: Public homepage
    host_pattern: "www.example.com"
    path_pattern: "/"
    public: true

  # Specific before wildcards
  - name: Admin
    host_pattern: "admin.example.com"
    permitted_roles: [admin]

  # Catch-all last
  - name: Default
    host_pattern: "*.example.com"
```

---

### 2. Longer Session Timeouts

**Trade-off:** Convenience vs. security

```yaml
server:
  session_timeout: 7d  # Stay logged in for a week
```

**Benefit:** Fewer login checks, faster access

**Cost:** Sessions persist longer (logout to revoke immediately)

---

### 3. Database on Fast Storage

**Slow:**
```yaml
volumes:
  - /mnt/network-nas/config:/config  # NFS/CIFS = slow
```

**Fast:**
```yaml
volumes:
  - auth-db:/config  # Local Docker volume = fast

volumes:
  auth-db:
    driver: local
```

---

### 4. Reverse Proxy Caching

Cache static assets (CSS, JS) at the proxy level.

**Traefik doesn't cache by default (use plugin or CDN)**

**Nginx example:**
```nginx
location ~* \.(css|js|png|jpg|gif)$ {
    proxy_cache my_cache;
    proxy_cache_valid 200 1d;
    proxy_pass http://auththingie:9000;
}
```

---

## Development

### Running Locally

**Prerequisites:**
- Go 1.25+ installed
- SQLite libraries: `apt install libsqlite3-dev` or `brew install sqlite3`

**Clone and run:**
```bash
git clone https://github.com/lthummus/auththingie2.git
cd auththingie2

# Install dependencies
go mod download

# Run locally
go run . serve

# Or build binary
go build -o auththingie2 .
./auththingie2 serve
```

**Config location:** Looks for `./auththingie2.yaml` in current directory.

---

### Running Tests

```bash
# All tests
go test ./...

# With coverage
go test -cover ./...

# Specific package
go test ./rules/

# Verbose
go test -v ./...

# Using gotestsum (nicer output)
gotestsum --format github-actions
```

---

### Generating Mocks

When interfaces change, regenerate mocks:

```bash
# Install mockery
go install github.com/vektra/mockery/v2@latest

# Regenerate all mocks
mockery --config .mockery.yml
```

---

### Code Structure

```
auththingie2/
├── cmd/              # Cobra CLI commands
├── handlers/         # HTTP request handlers
├── middlewares/      # HTTP middleware (sessions, security headers)
├── user/             # User management logic
├── rules/            # Access rule engine
├── totp/             # TOTP implementation
├── loginlimit/       # Rate limiting
├── db/sqlite/        # Database layer
├── config/           # Configuration types
├── render/           # Templates and static assets
├── ftue/             # First-time user experience
└── util/             # Shared utilities
```

**Key files:**
- `main.go` - Entry point
- `cmd/serve.go` - Server startup
- `handlers/*.go` - HTTP endpoints
- `rules/engine.go` - Rule evaluation logic

---

## Building from Source

### Local Build

```bash
# Build for current platform
go build -o auththingie2 .

# Build with optimizations
go build -ldflags="-s -w" -o auththingie2 .
```

---

### Docker Build

```bash
# Single architecture
docker build -t myuser/auththingie2:latest .

# Multi-architecture (requires buildx)
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t myuser/auththingie2:latest \
  --push \
  .
```

---

### Using Makefile

```bash
# Build Docker image
make docker

# Multi-architecture build
make multidocker
```

---

### Contributing

See the [Development Guidelines](../AGENTS.md) for detailed contributor expectations.

**Quick checklist:**
- [ ] Run tests: `go test ./...`
- [ ] Check code: `go vet ./...`
- [ ] Format code: `gofmt -w .`
- [ ] Security scan: `gosec ./...`
- [ ] Update tests for new features
- [ ] Add/update documentation

**Opening a PR:**
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make changes and commit
4. Push and open PR on GitHub
5. Describe changes clearly, include test evidence

---

## 🔗 Related Documentation

- **[Configuration Reference](configuration.md)** - All config options
- **[Architecture](architecture.md)** - How it works internally
- **[Troubleshooting](troubleshooting.md)** - Debug issues
- **[Development Guidelines](../AGENTS.md)** - Contributor checklist

---

[🏠 Back to Home](../README.md)
