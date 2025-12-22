# AuthThingie 2

AuthThingie2 (names are still hard) is a simple web server to be used with Traefik (and probably others) [Forward Authentication](https://doc.traefik.io/traefik/middlewares/http/forwardauth/). I originally wrote AuthThingie because I have a home server running a variety of services and I wanted one consistent authentication system (and Basic Auth is pretty cumbersome). 

Other applications such as [Keycloak](https://www.keycloak.org/) or [Authelia](https://www.authelia.com/) are good, but they are pretty heavy for just myself and a few friends. 

## What's New
AuthThingie2 improves on the original in a bunch of ways

1. **Passkey support**! AuthThingie supports passkeys for authenticating via biometrics on your mobile device without even having to type your username.
2. **User management via UI**! Users can be managed via webui instead of a configuration file and restarting the service.
3. **Rule hot-reloading**! Rules are still done via config file, but the configuration is hot-reloaded so when you change the rules, the config is instantly applied without restarting.
4. **A new First Time User Experience**! Instead of having to write your config file from the ground up the first time out, you can set everything up via web ui. You can also **import your AuthThingie 1 config file** so you can easily migrate.
5. **Smaller and faster**. AuthThingie2 was rewritten from the ground up.

## Setup and Installation

### Docker Setup
AuthThingie 2 is distributed as a Docker image. All you need to do is add a block to your `docker-compose.yaml` file and set up Forward Auth in Traefik.

An example Docker Compose block would look something like:

```yaml
  auth2:
    container_name: auth
    image: lthummus/auththingie2
    restart: unless-stopped
    volumes:
       - /path/to/your/config/auththingie2:/config
    environment:
      - PUID=${PUID}
      - PGID=${PGID}
      - TZ=${TIMEZONE}
    labels:
      - traefik.enable=true
      - traefik.http.services.auth.loadbalancer.server.port=9000
      - traefik.http.routers.auth.rule=Host(`auth.example.com`)
      - traefik.http.routers.auth.entrypoints=websecure
```

### Initial Configuration
By default, AuthThingie listens on port `9000`. Once you have this up and running, go to the site you've set up and you should be automatically forwarded to the setup flow. There, you'll be able to import your AuthThingie 1 file or start from scratch.

AuthThingie 2 will expect its configuration to be mounted at `/config` in the container, so make sure that is a mounted volume.

### Traefik Configuration

Once you've completed setup, you will have to create the Traefik Forward Auth config file, which will look like:

```yaml
http:
  middlewares:
    auththingie:
      forwardAuth:
        address: "http://auth:9000/auth"
```
And then tag every service you want to protect with 

```yaml
- traefik.http.routers.example.middlewares=auththingie@file
```

If you're not using Traefik, you'll have to figure this bit out on your own.

## Config File Structure

The config file should be named `auththingie2.yaml` and in the config directory (probably `/config`). The structure looks something like this:

```yaml
db:
  file: /config/at2.db
  kind: sqlite
security:
  trusted_proxies:
    network:
      - "172.18.0.0/16"
rules:
  - name: /css* on test.example.com
    host_pattern: test.example.com
    path_pattern: /css*
    public: true
  - name: /colors* on test.example.com
    host_pattern: test.example.com
    path_pattern: /colors*
    permitted_roles:
      - color_role
server:
  auth_url: https://example.com
  domain: example.com
  port: 9000
```

* The `db` section describes your backing database. Right now the only `kind` we support is `sqlite` and `file` should point to your SQLite database.
* The `rules` section describes rules. Each rule should have a name. You also should have some matching like `host_pattern`, `path_pattern` (`*` wildcards supported!) or `source_ip` (which should be a CIDR)
* The `server` section has some server configuration. The `auth_url` should be the URL that AuthThingie 2 lives at. `domain` should be the root domain (for example if you are protecting `a.example.com` and `b.example.com`, you should put `example.com`). `port` should be self-explanatory

#### Hidden Options

These exist, document later (including the secret debugging commands).



