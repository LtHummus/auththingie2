package handlers

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/internal/config"
	"github.com/lthummus/auththingie2/internal/middlewares/session"
	"github.com/lthummus/auththingie2/internal/render"
	"github.com/lthummus/auththingie2/internal/rules"
	"github.com/lthummus/auththingie2/internal/trueip"
	"github.com/lthummus/auththingie2/internal/user"
)

const (
	httpMethodHeader      = "X-Forwarded-Method"
	protocolHeader        = "X-Forwarded-Proto"
	hostHeader            = "X-Forwarded-Host"
	requestURIHeader      = "X-Forwarded-Uri"
	sourceIPAddressHeader = "X-Forwarded-For"

	redirectURLParam  = "redirect_uri"
	loginMessageParam = "message"

	publicUsernameHeaderValue = "<auththingie2 public access>"
	publicUserIDHeaderValue   = "00000000-0000-0000-0000-000000000000"
)

func pullInfoFromRequest(r *http.Request) rules.RequestInfo {
	// one little note -- we get the source IP from the X-Forwarded-For header naively here. This is ok because the
	// forward auth request is a separate, constructed one from Traefik that we can trust and it is not a proxied request
	// we have to view with suspicion

	path, query := rules.NormalizeURI(r.Header.Get(requestURIHeader))

	return rules.RequestInfo{
		Method:      r.Header.Get(httpMethodHeader),
		Protocol:    strings.ToLower(r.Header.Get(protocolHeader)),
		Host:        rules.NormalizeHost(r.Header.Get(hostHeader)),
		RequestURI:  path,
		QueryString: query,
		SourceIP:    net.ParseIP(r.Header.Get(sourceIPAddressHeader)),
	}
}

func (e *Env) HandleNotAllowed(w http.ResponseWriter, r *http.Request) {
	username := "<not logged in>"

	if user := session.GetUserFromRequest(r); user != nil {
		username = user.Username
	}

	params := struct {
		Username string
	}{username}

	render.RenderWithStatusCode(w, http.StatusForbidden, "forbidden.gohtml", &params)
}

func (e *Env) HandleAccountDisabled(w http.ResponseWriter, r *http.Request) {
	username := "<not logged in>"

	if user := session.GetUserFromRequest(r); user != nil {
		username = user.Username
	}

	params := struct {
		Username string
	}{username}

	render.RenderWithStatusCode(w, http.StatusForbidden, "disabled.gohtml", &params)
}

func (e *Env) potentiallyAttachUser(w http.ResponseWriter, user *user.User) {
	if headerName := e.Configuration.GetString(config.ConfigKeyAttachUsernameAuthResponseHeader); headerName != "" {
		w.Header().Set(headerName, user.Username)
	}
	if headerName := e.Configuration.GetString(config.ConfigKeyAttachUserIDAuthResponseHeader); headerName != "" {
		w.Header().Set(headerName, user.Id)
	}
}

func (e *Env) HandleCheckRequest(w http.ResponseWriter, r *http.Request) {
	if !trueip.IsFromTrustedProxy(r) {
		http.Error(w, "forward auth request not from trusted proxy", http.StatusForbidden)
		return
	}

	ri := pullInfoFromRequest(r)
	log.
		Debug().
		Str("method", ri.Method).
		Str("protocol", ri.Protocol).
		Str("host", ri.Host).
		Str("requestURI", ri.RequestURI).
		Stringer("source_ip", ri.SourceIP).
		Msg("got request info")

	if !ri.Valid() {
		log.
			Error().
			Str("method", ri.Method).
			Str("protocol", ri.Protocol).
			Str("host", ri.Host).
			Str("requestURI", ri.RequestURI).
			Stringer("source_ip", ri.SourceIP).
			Msg("invalid request from proxy")
		http.Error(w, "invalid http request info from reverse proxy", http.StatusBadRequest)
		return
	}

	if !e.RedirectURLValidator.IsAllowed(ri.GetURL()) {
		http.Error(w, "invalid url attempted to be checked; this is probably a configuration error", http.StatusForbidden)
		return
	}

	// first, see if our request matches any rules defined
	rule := e.Analyzer.MatchesRule(&ri)
	if rule == nil {
		log.Debug().Interface("rule", nil).Msg("rule matching complete")
	} else {
		log.Debug().Str("rule", rule.Name).Msg("rule matching complete")
	}

	// if we have a rule and the rule is public, just allow the user through...there is nothing else we need to do
	if rule != nil && rule.Public {
		log.Debug().Str("rule", rule.Name).Msg("rule is public; allowing access")
		e.potentiallyAttachUser(w, &user.User{Id: publicUserIDHeaderValue, Username: publicUsernameHeaderValue})
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// otherwise, see if we have a logged in user
	user, source := session.GetUserFromRequestAllowFallback(r, ri.SourceIP.String(), e.PasswordValidator, e.Configuration.GetBool(config.ConfigKeyDisbaleBasicAuth))

	// basic auth user, but invalid credentials
	if user == nil && source == session.UserSourceBasicAuth {
		log.Warn().Str("ip", trueip.Find(r, e.Configuration)).Msg("invalid basic auth credentials or account locked")
		http.Error(w, "invalid credentials or account locked", http.StatusForbidden)
		return
	}

	// if the user is nil, that means they are not logged in and we can just prompt them to do so
	if user == nil {
		log.Debug().Str("username", "<not logged in>").Msg("redirecting to login page")
		e.redirectToLogin(w, r, ri, loginMessageNotLoggedIn)
		return
	}

	if source == session.UserSourceBasicAuth && user.TOTPEnabled() {
		log.Warn().Str("ip", trueip.Find(r, e.Configuration)).Str("username", user.Username).Msg("attempted forward auth w/ basic auth and TOTP enabled")
		http.Error(w, "Can not use basic auth with TOTP enabled", http.StatusForbidden)
		return
	}

	if source == session.UserSourceBasicAuth && len(user.StoredCredentials) > 0 {
		log.Warn().Str("ip", trueip.Find(r, e.Configuration)).Str("username", user.Username).Msg("attempted forward auth w/ basic auth and passkeys")
		http.Error(w, "Can not use basic auth with passkeys enabled", http.StatusForbidden)
		return
	}

	if user.Disabled {
		log.Warn().Str("ip", trueip.Find(r, e.Configuration)).Str("username", user.Username).Msg("account disabled, forwarding to message")
		http.Redirect(w, r, fmt.Sprintf("%s/disabled", e.Configuration.GetString(config.ConfigKeyServerAuthURL)), http.StatusFound)
		return
	}

	log.Debug().Str("username", user.Username).Bool("is_admin", user.Admin).Strs("groups", user.Roles).Msg("detected logged in user")

	sess := session.GetSessionFromRequest(r)
	if rule != nil && rule.Timeout != nil && source == session.UserSourceSession && time.Since(sess.LoginTime) > *rule.Timeout {
		// user has logged in, but not since the timeout, so prompt for relogin
		log.Warn().Str("user_id", sess.UserID).Time("login_time", sess.LoginTime).Dur("rule_timeout", *rule.Timeout).Msg("need to reauthenticate")
		e.redirectToLogin(w, r, ri, loginMessageRuleRequiresSecondLogin)
		return
	}

	// next, check to see if the user is admin (implicitly allowed everything) or is in the group that allows
	// access to that url
	if user.Admin || (rule != nil && user.GroupsOverlap(rule.PermittedRoles)) {
		e.potentiallyAttachUser(w, user)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// if we're here, that means we are logged in and are denied access, return an error
	http.Redirect(w, r, fmt.Sprintf("%s/forbidden", e.Configuration.GetString(config.ConfigKeyServerAuthURL)), http.StatusFound)
}

func (e *Env) redirectToLogin(w http.ResponseWriter, r *http.Request, ri rules.RequestInfo, messageKey string) {
	v := url.Values{}

	// safe to use ri.GetURL because it should be checked earlier in the flow with `IsAllowed`
	v.Set(redirectURLParam, ri.GetURL())
	if messageKey != "" {
		v.Set(loginMessageParam, messageKey)
	}
	http.Redirect(w, r, fmt.Sprintf("%s/login?%s", e.Configuration.GetString(config.ConfigKeyServerAuthURL), v.Encode()), http.StatusFound)
}
