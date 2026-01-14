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
		s, err := base64.RawURLEncoding.DecodeString(mldsa65Seed)
		if err != nil {
			return fmt.Errorf("failed to decode seed: %w", err)
		}
		if len(s) != 32 {
			return fmt.Errorf("invalid seed length: expected 32 bytes, got %d", len(s))
		}
		copy(seed[:], s)
	} else {
		if _, err := rand.Read(seed[:]); err != nil {
			return fmt.Errorf("failed to generate random seed: %w", err)
		}
	}
	
	pub, err := mldsa65.NewKeyFromSeed(&seed)
	if err != nil {
		return fmt.Errorf("failed to generate key from seed: %w", err)
	}
	
	output := fmt.Sprintf("\n  Seed: %v\nVerify: %v",
		base64.RawURLEncoding.EncodeToString(seed[:]),
		base64.RawURLEncoding.EncodeToString(pub.Bytes()))
	fmt.Println(output)
	
	return nil
}