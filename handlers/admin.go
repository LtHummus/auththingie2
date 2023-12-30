package handlers

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/middlewares/session"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/rules"
	"github.com/lthummus/auththingie2/user"
)

type adminParams struct {
	Users []*user.AdminListUser
	Rules []*rules.DisplayableRule
}

type ruleTestParams struct {
	Rule  *rules.Rule
	Error string
}

func (e *Env) HandleTestRule(w http.ResponseWriter, r *http.Request) {
	u := session.GetUserFromRequest(r)
	if u == nil || !u.Admin {
		http.Error(w, "you cannot access this page", http.StatusForbidden)
		return
	}

	rawSource := strings.TrimSpace(r.FormValue("source"))
	if rawSource == "" {
		rawSource = "11.11.11.11" // TODO: is this a good idea?
	}

	source := net.ParseIP(rawSource)
	if source == nil {
		log.Warn().Str("ip", rawSource).Msg("invalid source IP given to test")
		render.Render(w, "rule_matched.gohtml", ruleTestParams{
			Error: "Invalid source IP",
		})
		return
	}

	rawURL := strings.TrimSpace(r.FormValue("url"))
	if rawURL == "" {
		render.Render(w, "rule_matched.gohtml", ruleTestParams{
			Error: "URL to test was blank",
		})
		return
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		log.Warn().Err(err).Str("url", rawURL).Msg("invalid URL to test")
		render.Render(w, "rule_matched.gohtml", ruleTestParams{
			Error: fmt.Sprintf("Invalid URL to test: %s", err.Error()),
		})
		return
	}

	ri := &rules.RequestInfo{
		Method:     http.MethodGet,
		Protocol:   parsedURL.Scheme,
		Host:       parsedURL.Host,
		RequestURI: parsedURL.Path,
		SourceIP:   source,
	}

	rule := e.Analyzer.MatchesRule(ri)
	render.Render(w, "rule_matched.gohtml", ruleTestParams{
		Rule: rule,
	})
}

type editUserParams struct {
	Error        string
	IsSelf       bool
	User         *user.User
	MissingRoles []string
	CSRFField    template.HTML
	CSRFToken    string
}

func (e *Env) HandleUserPatchTagsModification(w http.ResponseWriter, r *http.Request) {
	if loggedIn := session.GetUserFromRequest(r); loggedIn == nil || !loggedIn.Admin {
		render.RenderHTMXCompatibleError(w, r, "You must be logged in as admin to do this", "tag-error")
		return
	}

	userId := mux.Vars(r)["userId"]
	u, err := e.Database.GetUserByGuid(r.Context(), userId)
	if err != nil {
		log.Error().Err(err).Str("user_id", userId).Msg("could not get user from database")
		render.RenderHTMXCompatibleError(w, r, fmt.Sprintf("Could not get user from database: %s", err.Error()), "tag-error")
		return
	}
	if u == nil {
		log.Error().Str("user_id", userId).Msg("user not found in database")
		render.RenderHTMXCompatibleError(w, r, "User not found in database", "tag-error")
		return
	}

	tagName := r.FormValue("new-tag")
	if strings.TrimSpace(tagName) == "" {
		render.RenderHTMXCompatibleError(w, r, "Tag can not be blank", "tag-error")
		return
	}

	for _, curr := range u.Roles {
		if curr == tagName {
			render.RenderHTMXCompatibleError(w, r, fmt.Sprintf("Tag `%s` already exists on user", tagName), "tag-error")
			return
		}
	}

	u.Roles = append(u.Roles, tagName)
	err = e.Database.SaveUser(r.Context(), u)
	if err != nil {
		log.Error().Err(err).Str("user_id", u.Id).Strs("new_roles", u.Roles).Msg("could not update user roles")
		render.RenderHTMXCompatibleError(w, r, fmt.Sprintf("Could not update user in database: %s", err.Error()), "tag-error")
		return
	}

	render.Render(w, "tagtableinternal.gohtml", &editUserParams{
		User:         u,
		MissingRoles: e.buildMissingRoles(u),
		CSRFField:    csrf.TemplateField(r),
	})

}

func (e *Env) HandleUserTagDelete(w http.ResponseWriter, r *http.Request) {
	if logged := session.GetUserFromRequest(r); logged == nil || !logged.Admin {
		render.RenderHTMXCompatibleError(w, r, "You must be logged in as admin to do this", "tag-error")
		return
	}

	vars := mux.Vars(r)
	tagToDelete := vars["tag"]
	userId := vars["userId"]

	u, err := e.Database.GetUserByGuid(r.Context(), userId)
	if err != nil {
		log.Error().Err(err).Str("user_id", userId).Msg("could not get user from database")
		render.RenderHTMXCompatibleError(w, r, fmt.Sprintf("Could not get user from database: %s", err.Error()), "tag-error")
		return
	}
	if u == nil {
		log.Error().Str("user_id", userId).Msg("user not found in database")
		render.RenderHTMXCompatibleError(w, r, "User not found in database", "tag-error")
		return
	}

	newRoles := make([]string, 0)
	for _, curr := range u.Roles {
		if curr != tagToDelete {
			newRoles = append(newRoles, curr)
		}
	}
	u.Roles = newRoles
	err = e.Database.SaveUser(r.Context(), u)
	if err != nil {
		log.Error().Err(err).Str("user_id", u.Id).Strs("new_roles", newRoles).Msg("could not update user roles")
		render.RenderHTMXCompatibleError(w, r, fmt.Sprintf("Could not update user in database: %s", err.Error()), "tag-error")
		return
	}

	render.Render(w, "tagtableinternal.gohtml", &editUserParams{
		User:         u,
		MissingRoles: e.buildMissingRoles(u),
		CSRFField:    csrf.TemplateField(r),
	})
}

func (e *Env) buildMissingRoles(u *user.User) []string {
	var missingRoles []string
	for _, curr := range e.Analyzer.KnownRoles() {
		if !u.HasRole(curr) {
			missingRoles = append(missingRoles, curr)
		}
	}
	return missingRoles
}

func (e *Env) RenderUserEditPage(w http.ResponseWriter, r *http.Request) {
	logged := session.GetUserFromRequest(r)
	if logged == nil || !logged.Admin {
		http.Error(w, "you must be an admin to do this", http.StatusForbidden)
		return
	}

	userId := mux.Vars(r)["userId"]
	u, err := e.Database.GetUserByGuid(r.Context(), userId)
	if err != nil {
		log.Error().Err(err).Str("user_id", userId).Msg("could not get user info")
		http.Error(w, "could not get user info", http.StatusInternalServerError)
		return
	}
	if u == nil {
		http.Error(w, "user does not exist", http.StatusNotFound)
		return
	}
	render.Render(w, "edit_user.gohtml", editUserParams{
		User:         u,
		IsSelf:       u.Id == logged.Id,
		MissingRoles: e.buildMissingRoles(u),
		CSRFField:    csrf.TemplateField(r),
		CSRFToken:    csrf.Token(r),
	})
}

func (e *Env) HandleEditUserSubmission(w http.ResponseWriter, r *http.Request) {
	if logged := session.GetUserFromRequest(r); logged == nil || !logged.Admin {
		http.Error(w, "you must be an admin for this", http.StatusForbidden)
		return
	}

	userId := mux.Vars(r)["userId"]
	u, err := e.Database.GetUserByGuid(r.Context(), userId)
	if err != nil {
		log.Error().Err(err).Str("user_id", userId).Msg("could not get user")
		http.Error(w, "could not get user", http.StatusInternalServerError)
		return
	}
	if u == nil {
		log.Warn().Str("user_id", userId).Msg("could not find user")
		http.Error(w, "could not find user", http.StatusNotFound)
		return
	}

	newPwd := r.FormValue("new-pwd")
	if strings.TrimSpace(newPwd) != "" {
		err := u.SetPassword(newPwd)
		if err != nil {
			log.Error().Err(err).Msg("could not set user password")
			http.Error(w, "could not set user password", http.StatusInternalServerError)
			return
		}

		err = e.Database.SaveUser(r.Context(), u)
		if err != nil {
			log.Error().Err(err).Msg("could not persist changes to database")
			http.Error(w, "could not persist changes to database", http.StatusInternalServerError)
			return
		}

	}

	http.Redirect(w, r, "/admin", http.StatusFound)

}

func (e *Env) HandleAdminPage(w http.ResponseWriter, r *http.Request) {
	u := session.GetUserFromRequest(r)
	if u == nil || !u.Admin {
		http.Error(w, "you cannot access this page", http.StatusForbidden)
		return
	}

	allUsers, err := e.Database.GetAllUsers(r.Context())
	if err != nil {
		log.Error().Err(err).Msg("could not retrieve users from database")
		http.Error(w, "could not retrieve users from database", http.StatusInternalServerError)
		return
	}

	rawRules := e.Analyzer.Rules()

	allRules := make([]*rules.DisplayableRule, len(rawRules))
	for i := range rawRules {
		allRules[i] = rules.RuleToDisplayableRule(rawRules[i])
	}

	render.Render(w, "admin.gohtml", adminParams{
		Users: allUsers,
		Rules: allRules,
	})
}

type createUserPageParams struct {
	Username  string
	Error     string
	CSRFField template.HTML
}

func (e *Env) HandleCreateUserPage(w http.ResponseWriter, r *http.Request) {
	u := session.GetUserFromRequest(r)
	if u == nil || !u.Admin {
		http.Error(w, "you must be an admin to access this page", http.StatusUnauthorized)
		return
	}

	render.Render(w, "create_user_page.gohtml", &createUserPageParams{
		CSRFField: csrf.TemplateField(r),
	})
}

func (e *Env) HandleCreateUserPost(w http.ResponseWriter, r *http.Request) {
	u := session.GetUserFromRequest(r)
	if u == nil || !u.Admin {
		http.Error(w, "you must be an admin to access this page", http.StatusUnauthorized)
		return
	}

	username := r.FormValue("username")
	if username == "" {
		render.Render(w, "create_user_page.gohtml", &createUserPageParams{
			Error:     "Username may not be blank",
			CSRFField: csrf.TemplateField(r),
		})
		return
	}

	pw1 := r.FormValue("pw1")
	pw2 := r.FormValue("pw2")

	if pw1 == "" {
		render.Render(w, "create_user_page.gohtml", &createUserPageParams{
			Error:     "Password may not be blank",
			Username:  username,
			CSRFField: csrf.TemplateField(r),
		})
		return
	}

	if pw1 != pw2 {
		render.Render(w, "create_user_page.gohtml", &createUserPageParams{
			Error:     "Passwords do not match",
			Username:  username,
			CSRFField: csrf.TemplateField(r),
		})
		return
	}

	eu, err := e.Database.GetUserByUsername(r.Context(), username)
	if err != nil {
		log.Error().Err(err).Str("username", username).Msg("could not query for existing user")
		render.Render(w, "create_user_page.gohtml", &createUserPageParams{
			Error:     "Could not query for username",
			Username:  username,
			CSRFField: csrf.TemplateField(r),
		})
		return
	}

	if eu != nil {
		render.Render(w, "create_user_page.gohtml", &createUserPageParams{
			Error:     "Username already exists",
			Username:  username,
			CSRFField: csrf.TemplateField(r),
		})
		return
	}

	nu := &user.User{
		Username: username,
	}
	err = nu.SetPassword(pw1)
	if err != nil {
		log.Error().Err(err).Msg("could not set password")
		render.Render(w, "create_user_page.gohtml", &createUserPageParams{
			Error:     "Could not hash password",
			Username:  username,
			CSRFField: csrf.TemplateField(r),
		})
		return
	}

	err = e.Database.CreateUser(r.Context(), nu)
	if err != nil {
		log.Error().Err(err).Str("username", username).Msg("could not create user in database")
		render.Render(w, "create_user_page.gohtml", &createUserPageParams{
			Error:     "Could not create user in database",
			Username:  username,
			CSRFField: csrf.TemplateField(r),
		})
		return
	}

	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (e *Env) HandleAdminUnenrollTOTP(w http.ResponseWriter, r *http.Request) {
	u := session.GetUserFromRequest(r)
	if u == nil || !u.Admin {
		http.Error(w, "you must be an admin to access this page", http.StatusUnauthorized)
		return
	}

	userId := mux.Vars(r)["userId"]
	if u.Id == userId {
		log.Warn().Str("user_id", userId).Msg("tried to admin uneroll self")
		http.Error(w, "to unenroll yourself, you must use the normal method", http.StatusUnprocessableEntity)
		return
	}

	userToModify, err := e.Database.GetUserByGuid(r.Context(), userId)
	if err != nil {
		log.Warn().Err(err).Str("user_id", userId).Msg("could not get user from database")
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	if userToModify == nil {
		log.Warn().Str("user_id", userId).Msg("user not found")
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	userToModify.TOTPSeed = nil
	err = e.Database.SaveUser(r.Context(), userToModify)
	if err != nil {
		log.Warn().Str("user_id", userId).Err(err).Msg("could not save user to database")
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/admin/users/%s", userId), http.StatusFound)
}

func (e *Env) HandleUserDelete(w http.ResponseWriter, r *http.Request) {
	u := session.GetUserFromRequest(r)
	if u == nil || !u.Admin {
		http.Error(w, "you must be an admin to access this page", http.StatusUnauthorized)
		return
	}

	userId := mux.Vars(r)["userId"]

	if u.Id == userId {
		log.Warn().Str("user_id", userId).Msg("tried to delete self")
		http.Error(w, "you cannot delete yourself", http.StatusUnprocessableEntity)
		return
	}

	err := e.Database.DeleteUser(r.Context(), userId)
	if err != nil {
		// TODO: clean this up, render error a bit nicer
		log.Warn().Str("user_id", userId).Err(err).Msg("could not delete user")
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusFound)
}
