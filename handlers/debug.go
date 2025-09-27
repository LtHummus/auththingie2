package handlers

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/viper"

	"github.com/lthummus/auththingie2/config"
	"github.com/lthummus/auththingie2/middlewares/session"
	"github.com/lthummus/auththingie2/render"
	"github.com/lthummus/auththingie2/salt"
	"github.com/lthummus/auththingie2/util"
)

type debugPageInfo struct {
	DependencyTemplate template.HTML
	VarsTemplate       template.HTML
	ConfigTemplate     template.HTML
	BuildTemplate      template.HTML
	EnvVarTemplate     template.HTML
	RequestTemplate    template.HTML
	UserTemplate       template.HTML
	SessionTemplate    template.HTML
}

func (e *Env) HandleDebug(w http.ResponseWriter, r *http.Request) {
	u := session.GetUserFromRequest(r)
	if (u == nil || !u.Admin || u.Disabled) && !config.EnableDebugPage() {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	data := table.NewWriter()
	data.AppendHeader(table.Row{"Key", "Value"})
	data.AppendRows([]table.Row{
		{"CPU Count", runtime.NumCPU()},
		{"Goroutine Count", runtime.NumGoroutine()},
		{"CGO Count", runtime.NumCgoCall()},
	})

	buildInfo, _ := debug.ReadBuildInfo()

	buildTable := table.NewWriter()
	buildTable.AppendHeader(table.Row{"Key", "Value"})
	for _, curr := range buildInfo.Settings {
		buildTable.AppendRow(table.Row{curr.Key, curr.Value})
	}
	buildTable.AppendRow(table.Row{"Go Version", buildInfo.GoVersion})

	configTable := table.NewWriter()
	configTable.AppendHeader(table.Row{"Key", "Value"})
	configTable.AppendRows([]table.Row{
		{"Config File", viper.ConfigFileUsed()},
		{"TLS Enabled", viper.GetBool("server.tls.enabled")},
		{"Salt File Path", salt.GetSaltPath()},
	})
	absDbFile, err := filepath.Abs(viper.GetString("db.file"))
	if err != nil {
		configTable.AppendRow(table.Row{"DB File Path", fmt.Sprintf("Unable to get: %s", err.Error())})
	} else {
		configTable.AppendRow(table.Row{"DB File PAth", absDbFile})
	}

	depTable := table.NewWriter()
	depTable.AppendHeader(table.Row{"Path", "Version", "Sum"})
	for _, curr := range buildInfo.Deps {
		depTable.AppendRow(table.Row{curr.Path, curr.Version, curr.Sum})
	}

	envTable := table.NewWriter()
	envTable.AppendHeader(table.Row{"Key", "Value"})
	envTable.AppendRows([]table.Row{
		{"CONFIG_FILE_PATH", os.Getenv("CONFIG_FILE_PATH")},
		{"ENVIRONMENT", os.Getenv("ENVIRONMENT")},
		{"DEBUG_LOG", os.Getenv("DEBUG_LOG")},
		{"ENABLE_DEBUG_PAGE", os.Getenv("ENABLE_DEBUG_PAGE")},
		{"SALT_FILE", os.Getenv("SALT_FILE")},
	})

	cookieList := make([]string, 0)
	for _, curr := range r.Cookies() {
		cookieList = append(cookieList, curr.Name)
	}

	requestTable := table.NewWriter()
	requestTable.AppendHeader(table.Row{"Key", "Value"})
	requestTable.AppendRows([]table.Row{
		{"Host", r.Header.Get("Host")},
		{"RemoteAddr", r.RemoteAddr},
		{"User-Agent", r.Header.Get("User-Agent")},
		{"Cookies", strings.Join(cookieList, ", ")},
		{"X-Forwarded-For", r.Header.Get("X-Forwarded-For")},
		{"X-Forwarded-Host", r.Header.Get("X-Forwarded-Host")},
		{"X-Real-Ip", r.Header.Get("X-Real-Ip")},
		{"X-Forwarded-Server", r.Header.Get("X-Forwarded-Server")},
		{"util.FindTrueIP", util.FindTrueIP(r)},
	})

	userTable := table.NewWriter()
	userTable.AppendHeader(table.Row{"Key", "Value"})
	if u != nil {
		userTable.AppendRows([]table.Row{
			{"id", u.Id},
			{"username", u.Username},
			{"roles", strings.Join(u.Roles, ", ")},
			{"is_admin", fmt.Sprintf("%v", u.Admin)},
			{"totp_enabled", fmt.Sprintf("%v", u.TOTPEnabled())},
			{"password_timestamp", fmt.Sprintf("%d", u.PasswordTimestamp)},
			{"passkey_count", fmt.Sprintf("%d", len(u.StoredCredentials))},
		})
	}

	s := session.GetSessionFromRequest(r)

	sessionTable := table.NewWriter()
	sessionTable.AppendHeader(table.Row{"Key", "Value"})
	sessionTable.AppendRows([]table.Row{
		{"session_id", s.SessionID},
		{"user_id", s.UserID},
		{"login_time", s.LoginTime.Format(time.RFC1123)},
		{"expires", s.Expires.Format(time.RFC1123)},
		{"creation_time", s.CreationTime.Format(time.RFC1123)},
	})

	render.Render(w, "debug.gohtml", &debugPageInfo{
		DependencyTemplate: template.HTML(depTable.RenderHTML()),     // #nosec G203 -- table library handles escaping for us
		VarsTemplate:       template.HTML(data.RenderHTML()),         // #nosec G203
		BuildTemplate:      template.HTML(buildTable.RenderHTML()),   // #nosec G203
		ConfigTemplate:     template.HTML(configTable.RenderHTML()),  // #nosec G203
		EnvVarTemplate:     template.HTML(envTable.RenderHTML()),     // #nosec G203
		RequestTemplate:    template.HTML(requestTable.RenderHTML()), // #nosec G203
		UserTemplate:       template.HTML(userTable.RenderHTML()),    // #nosec G203
		SessionTemplate:    template.HTML(sessionTable.RenderHTML()), // #nosec G203
	})

}
