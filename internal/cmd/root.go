package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/lthummus/auththingie2/internal/server"
)

func init() {
	rootCmd.AddCommand(importEvalCmd)
	rootCmd.AddCommand(healthCheckCmd)
}

var rootCmd = &cobra.Command{
	Use:   "auththingie2",
	Short: "auththingie2 is a simple authentication layer for reverse proxies",
	Run: func(cmd *cobra.Command, args []string) {
		server.RunServer()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
}
