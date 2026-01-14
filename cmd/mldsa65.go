package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/spf13/cobra"
)

var (
	mldsa65Seed string
	mldsa65Cmd  = &cobra.Command{
		Use:   "mldsa65",
		Short: "Generate key pair for ML-DSA-65 post-quantum signature (REALITY)",
		Long: `Generate key pair for ML-DSA-65 post-quantum signature (REALITY).

Examples:
  Random:    mldsa65
  From seed: mldsa65 -i "seed (base64.RawURLEncoding)"`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := executeMLDSA65(); err != nil {
				fmt.Println(err)
			}
		},
	}
)

func init() {
	mldsa65Cmd.PersistentFlags().StringVarP(&mldsa65Seed, "input", "i", "", "Input seed (base64.RawURLEncoding, 32 bytes)")
	rootCmd.AddCommand(mldsa65Cmd)
}

func executeMLDSA65() error {
	var seed [32]byte
	
	if mldsa65Seed != "" {
		s, _ := base64.RawURLEncoding.DecodeString(mldsa65Seed)
		if len(s) != 32 {
			fmt.Println("Invalid length of ML-DSA-65 seed.")
			return
		}
		seed = [32]byte(s)
	} else {
		rand.Read(seed[:])
	}
	
	pub, _ := mldsa65.NewKeyFromSeed(&seed)
	output := fmt.Sprintf("\n  Seed: %v\nVerify: %v",
		base64.RawURLEncoding.EncodeToString(seed[:]),
		base64.RawURLEncoding.EncodeToString(pub.Bytes()))
	fmt.Println(output)
	
	return nil
}