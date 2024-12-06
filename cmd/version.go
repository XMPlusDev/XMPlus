package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version  = "v1.0.18"
	codename = "XMPlus "
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print current version of XMPlus",
		Run: func(cmd *cobra.Command, args []string) {
			showVersion()
		},
	})
}

func showVersion() {
    fmt.Printf("%s %s \n", version,codename)
}
