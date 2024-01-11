package handlers

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/middlewares/session"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/rules"
	"github.com/lthummus/auththingie2/util"
)

const (
	httpMethodHeader = "X-Forwarded-Method"
	protocolHeader   = "X-Forwarded-Proto"
	hostHeader       = "X-Forwarded-Host"
	requestURIHeader = "X-Forwarded-Uri"

	redirectURLParam  = "redirect_uri"
	loginMessageParam = "message"
)

func pullInfoFromRequest(r *http.Request) rules.RequestInfo {
	return rules.RequestInfo{
		Method:     r.Header.Get(httpMethodHeader),
		Protocol:   r.Header.Get(protocolHeader),
		Host:       r.Header.Get(hostHeader),
		RequestURI: r.Header.Get(requestURIHeader),
		SourceIP:   net.ParseIP(util.FindTrueIP(r)),
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

	w.WriteHeader(http.StatusForbidden)
	render.Render(w, "forbidden.gohtml", &params)
}

func (e *Env) HandleCheckRequest(w http.ResponseWriter, r *http.Request) {
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
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// otherwise, see if we have a logged in user
	user, source := session.GetUserFromRequestAllowFallback(r, e.Database)

	// if the user is nil, that means they are not logged in and we can just prompt them to do so
	if user == nil {
		log.Debug().Str("username", "<not logged in>").Msg("redirecting to login page")
		redirectToLogin(w, r, ri, "You are not logged in. Please log in.")
		return
	}

	log.Debug().Str("username", user.Username).Bool("is_admin", user.Admin).Strs("groups", user.Roles).Msg("detected logged in user")

	sess := session.GetSessionFromRequest(r)
	if rule != nil && rule.Timeout != nil && source == session.UserSourceSession && time.Since(sess.LoginTime) > *rule.Timeout {
		// user has logged in, but not since the timeout, so prompt for relogin
		log.Warn().Str("user_id", sess.UserID).Time("login_time", sess.LoginTime).Dur("rule_timeout", *rule.Timeout).Msg("need to reauthenticate")
		redirectToLogin(w, r, ri, "This matched rule requires you to log in again")
		return
	}

	// next, check to see if the user is admin (implicitly allowed everything) or is in the group that allows
	// access to that url
	if user.Admin || (rule != nil && user.GroupsOverlap(rule.PermittedRoles)) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// if we're here, that means we are logged in and are denied access, return an error
	http.Redirect(w, r, fmt.Sprintf("%s/forbidden", viper.GetString("server.auth_url")), http.StatusFound)
}

func redirectToLogin(w http.ResponseWriter, r *http.Request, ri rules.RequestInfo, message string) {
	v := url.Values{}
	v.Set(redirectURLParam, ri.GetURL())
	if message != "" {
		v.Set(loginMessageParam, message)
	}
	http.Redirect(w, r, fmt.Sprintf("%s/login?%s", viper.GetString("server.auth_url"), v.Encode()), http.StatusFound)
}
