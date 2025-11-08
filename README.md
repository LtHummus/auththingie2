# AuthThingie 2

> **Simple, lightweight forward authentication for your self-hosted services**

AuthThingie 2 is a modern authentication gateway designed for home labs and small teams. Protect your web services with a single sign-on system featuring passkey support, TOTP, and fine-grained access rules—all with a simple web UI setup.

---

## 📋 Table of Contents

- [Why AuthThingie 2?](#-why-auththingie-2)
- [Key Features](#-key-features)
- [Quick Start](#-quick-start)
- [Documentation](#-documentation)
- [What's New in v2](#-whats-new-in-v2)
- [Requirements](#-requirements)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Why AuthThingie 2?

**The Problem:** You're running multiple web services (Sonarr, Radarr, Grafana, etc.) on your home server. Setting up authentication for each one individually is tedious, and Basic Auth gets old fast. You want one centralized login that protects everything.

**The Solution:** AuthThingie 2 sits between your reverse proxy (like Traefik) and your services, providing:

- ✅ **Single Sign-On** - Log in once, access all your services
- ✅ **Modern Auth** - Passkeys (biometrics), TOTP 2FA, traditional passwords
- ✅ **Lightweight** - One small Docker container (vs. heavyweight solutions like Keycloak)
- ✅ **5-Minute Setup** - Guided web UI configuration, no YAML wrestling required
- ✅ **Flexible Rules** - Control access by domain, path, IP address, or user role

**Perfect for:** Home lab enthusiasts, small teams, anyone who wants secure access without enterprise complexity.

**Not ideal for:** Large organizations needing OAuth/SAML/LDAP integration, or services requiring federated identity.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔐 **Passkey Support** | Sign in with biometrics—no passwords needed |
| 👥 **Web-Based User Management** | Add/remove users through the UI, no config file editing |
| 🔄 **Hot-Reload Rules** | Update access rules instantly without restarting |
| 🎨 **First-Time Setup Wizard** | Guided configuration on first launch |
| 📦 **Import AuthThingie 1 Configs** | Migrate seamlessly from v1 |
| 🚀 **Fast & Tiny** | Written in Go, minimal resource footprint |
| 🛡️ **Flexible Access Control** | Rule-based authorization by host, path, IP, or role |

---

## 🚀 Quick Start

**Prerequisites:**
- Docker & Docker Compose installed
- A reverse proxy (Traefik recommended)
- A domain name pointing to your server

### Step 1: Add to Docker Compose

```yaml
services:
  auth:
    container_name: auth
    image: lthummus/auththingie2
    restart: unless-stopped
    volumes:
      - ./auththingie-config:/config
    environment:
      - TZ=America/New_York  # Your timezone
    labels:
      - traefik.enable=true
      - traefik.http.services.auth.loadbalancer.server.port=9000
      - traefik.http.routers.auth.rule=Host(`auth.example.com`)
      - traefik.http.routers.auth.entrypoints=websecure
      - traefik.http.routers.auth.tls=true
```

### Step 2: Configure Traefik Forward Auth

Create `traefik-config/dynamic/auththingie.yml`:

```yaml
http:
  middlewares:
    auththingie:
      forwardAuth:
        address: "http://auth:9000/forward"
```

### Step 3: Protect Your Services

Add this label to any service you want to protect:

```yaml
labels:
  - traefik.http.routers.myservice.middlewares=auththingie@file
```

### Step 4: Complete Setup

1. Start the container: `docker-compose up -d auth`
2. Visit `https://auth.example.com`
3. Follow the setup wizard to create your admin account
4. Start protecting your services!

**Next Steps:** See the [📚 Getting Started Guide](docs/getting-started.md) for detailed instructions.

---

## 📚 Documentation

### For Beginners
- **[Getting Started Guide](docs/getting-started.md)** - Step-by-step setup from scratch
- **[Core Concepts](docs/architecture.md#core-concepts)** - Understand how forward auth works
- **[FAQ](docs/faq.md)** - Common questions answered

### For Intermediate Users
- **[Configuration Reference](docs/configuration.md)** - Complete YAML schema documentation
- **[Access Rules Guide](docs/configuration.md#access-rules)** - Control who can access what
- **[Troubleshooting](docs/troubleshooting.md)** - Fix common issues

### For Advanced Users
- **[Architecture Overview](docs/architecture.md)** - How AuthThingie 2 works internally
- **[Advanced Scenarios](docs/advanced.md)** - Multiple domains, IP whitelisting, etc.
- **[Development Guide](docs/advanced.md#development)** - Build from source, contribute

---

## 🎉 What's New in v2

AuthThingie 2 is a complete rewrite with major improvements:

1. **Passkey Support** - Authenticate via biometrics on your phone without typing usernames
2. **Web-Based User Management** - No more editing config files to add users
3. **Hot-Reload Rules** - Change access rules without restarting the service
4. **Guided Setup Wizard** - No YAML editing required on first run
5. **Migration Tool** - Import AuthThingie 1 configs automatically
6. **Smaller & Faster** - Rewritten for better performance

[See full changelog →](https://github.com/lthummus/auththingie2/releases)

---

## 📦 Requirements

| Component | Requirement | Notes |
|-----------|-------------|-------|
| **Docker** | 20.10+ | Required for running the container |
| **Reverse Proxy** | Traefik 2.0+ | Or any proxy supporting forward auth |
| **Domain** | At least one | Can use a subdomain (auth.yourdomain.com) |
| **TLS Certificate** | Recommended | Required for passkeys; use Let's Encrypt |

**Knowledge Prerequisites:**
- Basic Docker Compose usage
- Basic understanding of reverse proxies
- Ability to edit YAML files

---

## 🤝 Contributing

Contributions are welcome! Please see the [Development Guidelines](AGENTS.md) for details.

**Found a bug?** [Open an issue](https://github.com/lthummus/auththingie2/issues)
**Have a question?** Check the [FAQ](docs/faq.md) first, then open a discussion

---

## 📄 License

This project is licensed under the MIT License. See the [MIT License](LICENSE) for the full text.

---

## 🔗 Links

- **Docker Hub:** [lthummus/auththingie2](https://hub.docker.com/r/lthummus/auththingie2)
- **Example Setup:** Browse the [example directory](example/)
- **Traefik Docs:** [Forward auth middleware](https://doc.traefik.io/traefik/middlewares/http/forwardauth/)

---

**Need help?** Start with the [Getting Started Guide](docs/getting-started.md) or check the [FAQ](docs/faq.md).
