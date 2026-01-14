package cmd

import (
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/spf13/cobra"
	
	"lukechampine.com/blake3"
)

var (
	mlkem768Seed string
	mlkem768Cmd  = &cobra.Command{
		Use:   "mlkem768",
		Short: "Generate key pair for ML-KEM-768 post-quantum key exchange (VLESS Encryption)",
		Long: `Generate key pair for ML-KEM-768 post-quantum key exchange (VLESS Encryption).

Examples:
  Random:    mlkem768
  From seed: mlkem768 -i "seed (base64.RawURLEncoding)"`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := executeMLKEM768(); err != nil {
				fmt.Println(err)
			}
		},
	}
)

func init() {
	mlkem768Cmd.PersistentFlags().StringVarP(&mlkem768Seed, "input", "i", "", "Input seed (base64.RawURLEncoding, 64 bytes)")
	rootCmd.AddCommand(mlkem768Cmd)
}

func executeMLKEM768() error {
	var seed [64]byte
	
	if mlkem768Seed != "" {
		s, err := base64.RawURLEncoding.DecodeString(mlkem768Seed)
		if err != nil {
			return fmt.Errorf("failed to decode seed: %w", err)
		}
		if len(s) != 64 {
			return fmt.Errorf("invalid seed length: expected 64 bytes, got %d", len(s))
		}
		copy(seed[:], s)
	} else {
		if _, err := rand.Read(seed[:]); err != nil {
			return fmt.Errorf("failed to generate random seed: %w", err)
		}
	}

	seed, client, hash32 := genMLKEM768(&seed)
	output := fmt.Sprintf("\n    Seed: %v\n  Client: %v\n Hash32: %v",
		base64.RawURLEncoding.EncodeToString(seed[:]),
		base64.RawURLEncoding.EncodeToString(client),
		base64.RawURLEncoding.EncodeToString(hash32[:]))
	fmt.Println(output)
	
	return nil
}

func genMLKEM768(inputSeed *[64]byte) (seed [64]byte, client []byte, hash32 [32]byte) {
	if inputSeed == nil {
		rand.Read(seed[:])
	} else {
		seed = *inputSeed
	}
	
	key, _ := mlkem.NewDecapsulationKey768(seed[:])
	client = key.EncapsulationKey().Bytes()
	sum := blake3.Sum256(client)
	hash32 = sum
	return
}