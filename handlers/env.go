package handlers

import (
	"net/http"

	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/config"
	"github.com/lthummus/auththingie2/loginlimit"
	"github.com/lthummus/auththingie2/middlewares/securityheaders"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/db"
	"github.com/lthummus/auththingie2/middlewares/session"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/rules"
)

type Env struct {
	Database     db.DB
	Analyzer     rules.Analyzer
	WebAuthn     *webauthn.WebAuthn
	LoginLimiter loginlimit.LoginLimiter
}

func (e *Env) BuildRouter() http.Handler {
	log.Info().Msg("setting up listeners")

	muxer := mux.NewRouter()

	muxer.HandleFunc("/forward", e.HandleCheckRequest)
	muxer.HandleFunc("/auth", e.HandleCheckRequest)
	muxer.HandleFunc("/forbidden", e.HandleNotAllowed)
	muxer.HandleFunc("/disabled", e.HandleAccountDisabled)

	muxer.HandleFunc("/debug", e.HandleDebug)

	muxer.HandleFunc("/login", e.HandleLoginPage)
	muxer.HandleFunc("/logout", e.HandleLogout)

	muxer.HandleFunc("/", e.HandleIndex).Methods(http.MethodGet)

	muxer.HandleFunc("/totp", e.HandleTOTPValidation)
	muxer.HandleFunc("/enable_totp", e.HandleTOTPSetup)
	muxer.HandleFunc("/disable_totp", e.HandleTOTPDisable)

	muxer.HandleFunc("/admin/users/create", e.HandleCreateUserPage).Methods(http.MethodGet)
	muxer.HandleFunc("/admin/users/create", e.HandleCreateUserPost).Methods(http.MethodPost)
	muxer.HandleFunc("/admin/users/{userId}", e.RenderUserEditPage).Methods(http.MethodGet)
	muxer.HandleFunc("/admin/users/{userId}", e.HandleEditUserSubmission).Methods(http.MethodPost)
	muxer.HandleFunc("/admin/users/{userId}/totp_unenroll", e.HandleAdminUnenrollTOTP).Methods(http.MethodPost)
	muxer.HandleFunc("/admin/users/{userId}/delete", e.HandleUserDelete).Methods(http.MethodPost)
	muxer.HandleFunc("/admin/users/{userId}/tags", e.HandleUserPatchTagsModification).Methods(http.MethodPatch)
	muxer.HandleFunc("/admin/users/{userId}/tags/{tag}", e.HandleUserTagDelete).Methods(http.MethodDelete)
	muxer.HandleFunc("/admin/users/{userId}/disable", e.HandleUserDisableEnable).Methods(http.MethodPatch)
	muxer.HandleFunc("/admin/ruletest", e.HandleTestRule).Methods(http.MethodGet)
	muxer.HandleFunc("/admin", e.HandleAdminPage).Methods(http.MethodGet)

	muxer.HandleFunc("/edit_self", e.HandleSelfConfigGet).Methods(http.MethodGet)
	muxer.HandleFunc("/edit_self/password", e.HandleSelfConfigPasswordGet).Methods(http.MethodGet)
	muxer.HandleFunc("/edit_self/password", e.HandleSelfConfigPasswordPost).Methods(http.MethodPost)

	muxer.HandleFunc("/webauthn/manage", e.HandleRenderWebAuthnManage)
	muxer.HandleFunc("/webauthn/register", e.HandleWebAuthnBeginRegistration)
	muxer.HandleFunc("/webauthn/finishregister", e.HandleWebAuthnFinishRegistration)
	muxer.HandleFunc("/webauthn/discover", e.HandleWebAuthnBeginDiscoverableLogin)
	muxer.HandleFunc("/webauthn/finishdiscover", e.HandleWebAuthnFinishDiscoverableLogin)
	muxer.HandleFunc("/webauthn/keys/{keyId}", e.HandleWebAuthnEditKey)
	muxer.HandleFunc("/webauthn/keys/{keyId}/edit", e.HandleWebAuthnEditKey)
	muxer.HandleFunc("/webauthn/keys", e.GetEnrolledPasskeyKeyIDs)

	muxer.PathPrefix("/static/").Handler(render.StaticFSHandler())

	sessionMiddleware := session.NewMiddleware(muxer, e.Database)

	cop := http.NewCrossOriginProtection()
	cop.AddInsecureBypassPattern("/forward")
	cop.AddInsecureBypassPattern("/auth")
	cop.AddInsecureBypassPattern("/forbidden")
	cop.AddInsecureBypassPattern("/disabled")

	handler := cop.Handler(sessionMiddleware)

	if viper.GetBool(config.DisableSecurityHeaders) {
		log.Warn().Msg("not enabling security headers")
		handler = securityheaders.NewSecurityHeadersMiddleware(handler)
	}

	return handler
}
