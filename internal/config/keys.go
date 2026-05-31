package config

const (
	ConfigKeyKeyPasskeysDisabled    = "passkeys.disabled"
	ConfigKeyDefaultCookieLifetime  = "session.cookie.timeout"
	ConfigKeyDefaultSessionLifetime = "session.timeout"

	ConfigKeyAttachUsernameAuthResponseHeader = "auth.attach_username_header"
	ConfigKeyAttachUserIDAuthResponseHeader   = "auth.attach_userid_header"

	ConfigKeyDisableSecurityHeaders = "security.disable_headers"

	ConfigKeyServerPort      = "server.port"
	ConfigKeyServerDomain    = "server.domain"
	ConfigKeyServerAuthURL   = "server.auth_url"
	ConfigKeyServerSecretKey = "server.secret_key"

	ConfigKeyServerTLSEnabled  = "server.tls.enabled"
	ConfigKeyServerTLSKeyFile  = "server.tls.key_file"
	ConfigKeyServerTLSCertFile = "server.tls.cert_file"

	ConfigKeyDBKind = "db.kind"
	ConfigKeyDBFile = "db.file"

	ConfigKeyRules = "auththingie.rules"
	ConfigKeyUsers = "auththingie.users"

	ConfigKeyHealthcheckIgnoreBadTLS = "healthcheck.tls.ignore_bad_tls"

	ConfigKeyTrustedProxyNetwork        = "security.trusted_proxies.network"
	ConfigKeyTrustedProxyDockerEnabled  = "security.trusted_proxies.docker.enabled"
	ConfigKeyTrustedProxyDockerEndpoint = "security.trusted_proxies.docker.endpoint"
	ConfigKeyTrustedProxyIPHeader       = "security.real_ip_header"

	ConfigKeyLoginFailureLimit = "security.account_lock.failure_limit"
	ConfigKeyLookbackTime      = "security.account_lock.lookback_time"
	ConfigKeyLockDuration      = "security.account_lock.lock_duration"

	ConfigKeyRedirectsAllowAllKey       = "security.redirects.allow_all"
	ConfigKeyRedirectsFallbackURLKey    = "security.redirects.fallback_url"
	ConfigKeyRedirectsAllowedDomainsKey = "security.redirects.allowed_domains"

	ConfigKeyDisablePasswordMigrateOnLogin = "security.disable_migrate_on_login"

	ConfigKeyDisbalePRECIS = "security.disable_precis"

	ConfigKeyDisbaleBasicAuth = "security.disable_basic_auth"

	ConfigKeyHideAdminMessages = "unsafe_hide_admin_messages"
)
