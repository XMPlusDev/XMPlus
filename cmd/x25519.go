package cmd

import (
	"fmt"
	
	"github.com/spf13/cobra"
)

var (
	x25519PrivateKey string
	x25519StdEncoding bool
	x25519Cmd = &cobra.Command{
		Use:   "x25519",
		Short: "Generate key pair for X25519 key exchange (REALITY, VLESS Encryption)",
		Long: `Generate key pair for X25519 key exchange (REALITY, VLESS Encryption).

Examples:
  Random:           x25519
  From private key: x25519 -i "private key (base64.RawURLEncoding)"
  For Std Encoding: x25519 --std-encoding`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := executeX25519(); err != nil {
				fmt.Println(err)
			}
		},
	}
)

func init() {
	x25519Cmd.PersistentFlags().StringVarP(&x25519PrivateKey, "input", "i", "", "Input private key (base64.RawURLEncoding)")
	x25519Cmd.PersistentFlags().BoolVar(&x25519StdEncoding, "std-encoding", false, "Use standard base64 encoding instead of raw URL encoding")
	rootCmd.AddCommand(x25519Cmd)
}

func executeX25519() error {
	Curve25519Genkey(x25519StdEncoding, x25519PrivateKey)
	
	return nil
}