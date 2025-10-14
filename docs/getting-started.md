# Getting Started with AuthThingie 2

> **Beginner-friendly guide to set up AuthThingie 2 from scratch**

[🏠 Home](../README.md) • [📖 Configuration](configuration.md) • [🔧 Troubleshooting](troubleshooting.md)

---

## 🎯 What You'll Learn

By the end of this guide, you'll have:
- ✅ AuthThingie 2 running in Docker
- ✅ Traefik configured for forward authentication
- ✅ Your first service protected with login
- ✅ A user account with passkey or TOTP 2FA

**Time required:** 15-30 minutes
**Skill level:** Beginner (basic Docker & terminal knowledge)

---

## 📋 Prerequisites

Before starting, make sure you have:

### Required
- [ ] **Docker** (20.10+) and **Docker Compose** installed
- [ ] **Traefik** (2.0+) running as your reverse proxy
- [ ] A **domain name** pointing to your server (e.g., `example.com`)
- [ ] **Basic terminal skills** (editing files, running commands)

### Recommended
- [ ] **HTTPS/TLS** set up (required for passkeys, recommended for security)
- [ ] **Let's Encrypt** configured in Traefik for automatic certificates

### Not Sure If You Have These?

<details>
<summary>Check if Docker is installed</summary>

```bash
docker --version
docker-compose --version
```

If you see version numbers, you're good! If not, install Docker from the [Docker installation guide](https://docs.docker.com/get-docker/)
</details>

<details>
<summary>Check if Traefik is running</summary>

```bash
docker ps | grep traefik
```

If you see a traefik container, you're set. If not, see the [Traefik setup guide](https://doc.traefik.io/traefik/getting-started/quick-start/).
</details>

---

## 🚀 Step-by-Step Setup

### Step 1: Create Config Directory

First, create a directory to store AuthThingie's configuration:

```bash
mkdir -p ~/docker/auththingie2/config
cd ~/docker/auththingie2
```

> **Note:** You can put this anywhere, just remember the path.

---

### Step 2: Add to Docker Compose

Open your `docker-compose.yml` (or create one if starting fresh):

```yaml
version: '3.8'

services:
  auth:
    container_name: auththingie
    image: lthummus/auththingie2:latest
    restart: unless-stopped
    volumes:
      - ./config:/config
    environment:
      - TZ=America/New_York  # Change to your timezone
    labels:
      - "traefik.enable=true"
      - "traefik.http.services.auth.loadbalancer.server.port=9000"
      - "traefik.http.routers.auth.rule=Host(`auth.example.com`)"  # Change this!
      - "traefik.http.routers.auth.entrypoints=websecure"
      - "traefik.http.routers.auth.tls=true"
      - "traefik.http.routers.auth.tls.certresolver=letsencrypt"  # If using Let's Encrypt
```

**Important changes:**
1. Replace `auth.example.com` with your actual subdomain
2. Replace `America/New_York` with your timezone ([see list](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones))
3. Adjust `certresolver` name if you named yours differently

---

### Step 3: Start the Container

```bash
docker-compose up -d auth
```

Check that it started successfully:

```bash
docker-compose logs auth
```

You should see logs indicating the server started on port 9000.

---

### Step 4: Complete First-Time Setup

1. **Open your browser** and go to `https://auth.example.com` (use your domain)
2. You'll see the **First-Time Setup Wizard**
3. Choose one of two options:

   **Option A: Start Fresh**
   - Click "Create New Configuration"
   - Fill in these fields:
     - **Domain:** Your root domain (e.g., `example.com`)
     - **Auth URL:** Full URL to AuthThingie (e.g., `https://auth.example.com`)
   - Click "Continue"

   **Option B: Import from AuthThingie 1**
   - Click "Import Configuration"
   - Upload your old `auththingie.yaml` file
   - Review imported settings
   - Click "Import"

4. **Create your admin account:**
   - Choose a username
   - Set a strong password
   - (Optional) Set up a passkey or TOTP 2FA now

5. Click **"Complete Setup"**

You should now see the AuthThingie dashboard!

---

### Step 5: Configure Traefik Forward Auth

AuthThingie needs to tell Traefik how to validate requests. Create a Traefik dynamic configuration file:

#### Where to put this file:
- If using **file provider:** Place in your Traefik `dynamic/` config folder
- If unsure: Check your `traefik.yml` for the `file` provider directory

**Create `auththingie.yml`:**

```yaml
http:
  middlewares:
    auththingie:
      forwardAuth:
        address: "http://auththingie:9000/forward"
        trustForwardHeader: true
        authResponseHeaders:
          - "X-Forwarded-User"
```

> **Note:** `auththingie` is the container name from Step 2. If you used a different name, change it here.

**Restart Traefik** to load the new config:

```bash
docker-compose restart traefik
```

---

### Step 6: Protect Your First Service

Let's protect an example service. Add the `auththingie` middleware to any service:

**Before:**
```yaml
services:
  sonarr:
    image: linuxserver/sonarr
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.sonarr.rule=Host(`sonarr.example.com`)"
      - "traefik.http.routers.sonarr.entrypoints=websecure"
      - "traefik.http.routers.sonarr.tls=true"
```

**After (with auth):**
```yaml
services:
  sonarr:
    image: linuxserver/sonarr
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.sonarr.rule=Host(`sonarr.example.com`)"
      - "traefik.http.routers.sonarr.entrypoints=websecure"
      - "traefik.http.routers.sonarr.tls=true"
      - "traefik.http.routers.sonarr.middlewares=auththingie@file"  # ← Add this line
```

**Apply changes:**
```bash
docker-compose up -d sonarr
```

---

### Step 7: Test It Out!

1. **Open a new private/incognito browser window**
2. Go to `https://sonarr.example.com` (your protected service)
3. You should be **redirected to the login page**
4. Log in with the account you created
5. You should be **redirected back to Sonarr**

🎉 **Success!** Your service is now protected!

---

## 🎨 Next Steps

### Add More Users

1. Log into AuthThingie at `https://auth.example.com`
2. Go to **"Users"** in the sidebar
3. Click **"Add User"**
4. Fill in details and click **"Create"**

Users can set up their own passkeys and TOTP after first login.

### Set Up Access Rules

By default, all authenticated users can access all services. To restrict access:

1. Go to **"Rules"** in AuthThingie
2. See the [Configuration Guide](configuration.md#access-rules) for rule syntax

### Enable Passkeys (Recommended)

Passkeys provide the best security and convenience:

1. Log into AuthThingie
2. Click your username (top right)
3. Go to **"Security"**
4. Click **"Add Passkey"**
5. Follow the prompts on your device

> **Requirements:** HTTPS must be enabled (Let's Encrypt certificates work perfectly)

---

## ❓ Common Issues

### "502 Bad Gateway" when accessing auth.example.com

**Cause:** AuthThingie container isn't running or Traefik can't reach it.

**Fix:**
```bash
# Check if container is running
docker ps | grep auththingie

# Check logs for errors
docker-compose logs auth

# Restart the container
docker-compose restart auth
```

### Stuck in redirect loop

**Cause:** Traefik middleware not configured correctly.

**Fix:**
1. Verify `auththingie.yml` is in Traefik's dynamic config folder
2. Check Traefik logs: `docker-compose logs traefik`
3. Ensure the middleware name matches: `auththingie@file`

### Login page loads but can't log in

**Cause:** Database or session cookie issues.

**Fix:**
1. Check that `/config` volume is mounted and writable
2. Verify `domain` in config matches your root domain
3. Clear browser cookies and try again

### Passkey setup fails

**Cause:** HTTPS not properly configured.

**Fix:**
- Passkeys **require HTTPS**
- Check that `tls=true` is set in Traefik labels
- Verify certificate is valid (not self-signed)

**More help:** See the [Troubleshooting Guide](troubleshooting.md)

---

## 📚 Learn More

- **[Configuration Reference](configuration.md)** - All config options explained
- **[Architecture Overview](architecture.md)** - How forward auth works
- **[Advanced Scenarios](advanced.md)** - Multiple domains, IP whitelisting
- **[FAQ](faq.md)** - Frequently asked questions

---

## 🆘 Still Stuck?

- Check the [FAQ](faq.md)
- Review [Troubleshooting Guide](troubleshooting.md)
- Look at the [example setup](../example/) in this repo
- Open an [issue on GitHub](https://github.com/lthummus/auththingie2/issues)

---

[🏠 Back to Home](../README.md)
