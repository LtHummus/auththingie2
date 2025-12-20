# AuthThingie 2 Documentation

> **Complete documentation hub for AuthThingie 2**

[🏠 Back to Project Home](../README.md)

---

## 📚 Documentation Index

Welcome to the AuthThingie 2 documentation! Choose your path based on your experience level.

---

## 🚀 Getting Started

**New to AuthThingie?** Start here!

### [Getting Started Guide](getting-started.md)
Step-by-step tutorial to get AuthThingie running in 15-30 minutes.

**You'll learn:**
- Prerequisites and system requirements
- Docker Compose setup
- Traefik configuration
- First-time setup wizard
- Protecting your first service

**Perfect for:** Beginners, first-time users

---

## 📖 Core Documentation

### [Reverse Proxy Primer](reverse-proxy-primer.md)
**New to reverse proxies?** This gentle introduction explains what they are, why you need one, and how to set up popular options like Traefik, Nginx, and Caddy.

**Topics covered:**
- What is a reverse proxy?
- Why use one?
- Comparison of popular solutions (Traefik, Nginx, Caddy, HAProxy)
- Setup guides for each
- Integration with AuthThingie

**Perfect for:** Beginners, those without a reverse proxy

---

### [Configuration Reference](configuration.md)
Complete reference for all configuration options in `auththingie2.yaml`.

**Topics covered:**
- Server configuration (port, domain, auth_url)
- Database settings
- Access rules (patterns, users, roles, IPs)
- Session management
- Security options
- Environment variables
- Configuration examples

**Perfect for:** Intermediate users, fine-tuning your setup

---

### [Architecture & Core Concepts](architecture.md)
Deep dive into how AuthThingie 2 works under the hood.

**Topics covered:**
- Forward authentication explained
- Request flow diagrams
- Component architecture
- Authentication methods (passwords, passkeys, TOTP)
- Session management
- Security model

**Perfect for:** Understanding the "why" behind the "how"

---

## 🛠️ Troubleshooting & Support

### [Troubleshooting Guide](troubleshooting.md)
Fix common issues and debug problems.

**Topics covered:**
- Quick diagnostics checklist
- Cannot access AuthThingie
- Login failures
- Redirect loop problems
- Services not protected
- Passkey issues
- Configuration errors
- Performance problems
- Getting help

**Perfect for:** When things aren't working

---

### [FAQ](faq.md)
Quick answers to frequently asked questions.

**Topics covered:**
- General questions (what, why, how)
- Setup & installation
- Authentication & security
- Configuration
- Compatibility
- Common issues

**Perfect for:** Quick reference, common questions

---

## 🎓 Advanced Topics

### [Advanced Usage Guide](advanced.md)
Complex scenarios, optimization, and development.

**Topics covered:**
- Multiple domains
- IP whitelisting
- Role-based access control
- High availability setup
- Integration with other tools (Fail2Ban, Prometheus, Grafana)
- Reverse proxy alternatives (Nginx, Caddy, HAProxy)
- Performance optimization
- Building from source
- Contributing

**Perfect for:** Advanced users, developers

---

## 📊 Quick Reference

### Common Tasks

| Task | Guide | Section |
|------|-------|---------|
| First-time setup | [Getting Started](getting-started.md) | All |
| Add authentication to service | [Getting Started](getting-started.md) | Step 6 |
| Configure access rules | [Configuration](configuration.md) | Access Rules |
| Set up passkeys | [Getting Started](getting-started.md) | Next Steps |
| Enable TOTP 2FA | [FAQ](faq.md) | Authentication & Security |
| Fix redirect loop | [Troubleshooting](troubleshooting.md) | Redirect Loop Problems |
| Multiple domains | [Advanced](advanced.md) | Multiple Domains |
| IP whitelisting | [Advanced](advanced.md) | IP Whitelisting |
| Role-based access | [Advanced](advanced.md) | Role-Based Access Control |
| Choose reverse proxy | [Reverse Proxy Primer](reverse-proxy-primer.md) | Choosing the Right Proxy |
| Set up Traefik | [Reverse Proxy Primer](reverse-proxy-primer.md) | Setting Up Traefik |
| Set up Nginx | [Reverse Proxy Primer](reverse-proxy-primer.md) | Setting Up Nginx |

---

## 🎯 Documentation by Experience Level

### 👶 Beginner (No Docker/Traefik Experience)

**Recommended reading order:**
1. [Reverse Proxy Primer](reverse-proxy-primer.md) - Understand what you're building
2. [Getting Started](getting-started.md) - Follow step-by-step
3. [FAQ](faq.md) - Answer lingering questions
4. [Troubleshooting](troubleshooting.md) - When you get stuck

**Time investment:** 1-2 hours

---

### 🧑 Intermediate (Have Docker/Traefik, Want Auth)

**Recommended reading order:**
1. [Getting Started](getting-started.md) - Quick setup
2. [Configuration](configuration.md) - Customize for your needs
3. [Architecture](architecture.md) - Understand how it works
4. [FAQ](faq.md) - Reference

**Time investment:** 30-60 minutes

---

### 🧙 Advanced (Complex Setup, Multiple Domains, HA)

**Recommended reading order:**
1. [Getting Started](getting-started.md) - Basic setup first
2. [Configuration](configuration.md) - Learn all options
3. [Architecture](architecture.md) - Deep understanding
4. [Advanced](advanced.md) - Complex scenarios
5. [Troubleshooting](troubleshooting.md) - Debug issues

**Time investment:** 2-4 hours

---

## 🔗 External Resources

### Official Links
- **Docker Hub:** [AuthThingie 2 on Docker Hub](https://hub.docker.com/r/lthummus/auththingie2)
- **GitHub Repository:** [lthummus/auththingie2](https://github.com/lthummus/auththingie2)
- **Issue Tracker:** [Report an issue](https://github.com/lthummus/auththingie2/issues)

### Related Documentation
- **Traefik:** [Reverse proxy documentation](https://doc.traefik.io/traefik/)
- **Traefik Forward Auth:** [Forward auth middleware](https://doc.traefik.io/traefik/middlewares/http/forwardauth/)
- **Docker Compose:** [Compose documentation](https://docs.docker.com/compose/)
- **Let's Encrypt:** [Getting started guide](https://letsencrypt.org/getting-started/)
- **WebAuthn/Passkeys:** [webauthn.guide overview](https://webauthn.guide/)

### Community Resources
- **Reddit r/selfhosted:** [Community discussions](https://reddit.com/r/selfhosted)
- **Docker Community:** [Forums](https://forums.docker.com/)

---

## 📝 Contributing to Documentation

Found a typo? Have a suggestion? Documentation improvements are always welcome!

**How to contribute:**
1. Fork the repository
2. Edit files in `docs/` directory
3. Submit a pull request

**Guidelines:**
- Use clear, simple language
- Include examples where possible
- Test all commands/configs
- Add diagrams for complex concepts
- Keep formatting consistent

See the [Development Guidelines](../AGENTS.md) for contributor expectations.

---

## 🆘 Getting Help

**Stuck? Try these steps:**

1. **Search this documentation**
   - Use Ctrl+F / Cmd+F in your browser
   - Check the [FAQ](faq.md)
   - Review [Troubleshooting Guide](troubleshooting.md)

2. **Search existing issues**
   - [GitHub Issues](https://github.com/lthummus/auththingie2/issues)
   - Someone may have already solved your problem

3. **Open a new issue**
   - Provide detailed information
   - Include logs (sanitized)
   - Describe expected vs actual behavior
   - Mention versions (Docker, Traefik, AuthThingie)

4. **Community forums**
   - [r/selfhosted on Reddit](https://reddit.com/r/selfhosted)
   - [Docker community forums](https://forums.docker.com/)

---

## 📜 License

This documentation is part of the AuthThingie 2 project, licensed under the MIT License.

---

[🏠 Back to Project Home](../README.md)
