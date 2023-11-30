package cmd

import (
	"fmt"
	"os"
	"regexp"

	"github.com/hyperjumptech/jiffy"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/lthummus/auththingie2/importer"
)

var (
	at1FilePath string

	bcryptRegex = regexp.MustCompile(`^\$2[ayb]\$.{56}$`)
)

func init() {
	importEvalCmd.Flags().StringVarP(&at1FilePath, "file", "f", "", "AT1 config file to parse")
	_ = importEvalCmd.MarkFlagRequired("file")
}

func getOrDefault[T any](x *T, def T) T {
	if x != nil {
		return *x
	}
	return def
}

func validPasswordHash(x string) string {
	if bcryptRegex.MatchString(x) {
		return "VALID"
	}
	return "INVALID"
}

var importEvalCmd = &cobra.Command{
	Use:   "evalimport",
	Short: "Read an AuthThingie 1 config file to see what will get imported",
	Run: func(cmd *cobra.Command, args []string) {
		bytes, err := os.ReadFile(at1FilePath)
		if err != nil {
			log.Fatal().Err(err).Str("file", at1FilePath).Msg("could not read file")
		}

		r, err := importer.Import(string(bytes))
		if err != nil {
			log.Fatal().Err(err).Str("file", at1FilePath).Msg("could not parse file")
		}

		ruleTable := table.NewWriter()
		ruleTable.SetOutputMirror(os.Stdout)
		ruleTable.AppendHeader(table.Row{"#", "Name", "Timeout", "Protocol Pattern", "Host Pattern", "Path Pattern", "Public", "Permitted Roles"})

		for i, curr := range r.Rules {
			tout := "<default>"
			if curr.Timeout != nil {
				tout = jiffy.DescribeDuration(*curr.Timeout, jiffy.NewWant())
			}
			ruleTable.AppendRow(table.Row{fmt.Sprintf("%d\n", i+1),
				curr.Name,
				tout,
				getOrDefault(curr.ProtocolPattern, "*"),
				getOrDefault(curr.HostPattern, "*"),
				getOrDefault(curr.PathPattern, "*"),
				curr.Public,
				curr.PermittedRoles})
		}
		ruleTable.Render()

		userTable := table.NewWriter()
		userTable.SetOutputMirror(os.Stdout)
		userTable.AppendHeader(table.Row{"#", "Username", "Password Hash", "Roles", "Admin", "TOTP Enabled"})
		for i, curr := range r.Users {
			userTable.AppendRow(table.Row{fmt.Sprintf("%d\n", i+1),
				curr.Username,
				validPasswordHash(curr.PasswordHash),
				curr.Roles,
				curr.Admin,
				curr.TOTPEnabled(),
			})
		}
		userTable.Render()

		settingsTable := table.NewWriter()
		settingsTable.SetOutputMirror(os.Stdout)
		settingsTable.AppendHeader(table.Row{"Key", "Value"})
		settingsTable.AppendRows([]table.Row{
			{"Auth URL", r.AuthURL},
			{"Domain", r.Domain},
		})
		settingsTable.Render()
	},
}
