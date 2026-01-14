package cmd

import (
	"encoding/base64"
	"fmt"
	"strings"
	
	"github.com/spf13/cobra"
)

var vlessencCmd = &cobra.Command{
	Use:   "vlessenc",
	Short: "Generate decryption/encryption json pair (VLESS Encryption)",
	Long: `Generate decryption/encryption json pair (VLESS Encryption).

This command generates both X25519 and ML-KEM-768 authentication pairs.
Choose one authentication method to use - do not mix them.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := executeVLESSEnc(); err != nil {
			fmt.Println(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(vlessencCmd)
}

func executeVLESSEnc() error {
	// Generate X25519 keys
	privateKey, password, _, _ := genCurve25519(nil)
	serverKey := base64.RawURLEncoding.EncodeToString(privateKey)
	clientKey := base64.RawURLEncoding.EncodeToString(password)
	
	decryption := generateDotConfig("mlkem768x25519plus", "native", "600s", serverKey)
	encryption := generateDotConfig("mlkem768x25519plus", "native", "0rtt", clientKey)
	
	// Generate ML-KEM-768 keys
	seed, client, _ := genMLKEM768(nil)
	serverKeyPQ := base64.RawURLEncoding.EncodeToString(seed[:])
	clientKeyPQ := base64.RawURLEncoding.EncodeToString(client)
	
	decryptionPQ := generateDotConfig("mlkem768x25519plus", "native", "600s", serverKeyPQ)
	encryptionPQ := generateDotConfig("mlkem768x25519plus", "native", "0rtt", clientKeyPQ)
	
	// Print results
	fmt.Println("\nChoose one Authentication to use, do not mix them. Ephemeral key exchange is Post-Quantum safe anyway.\n")
	fmt.Printf("Authentication: X25519, not Post-Quantum\n\"decryption\": \"%v\"\n\"encryption\": \"%v\"\n\n", decryption, encryption)
	fmt.Printf("Authentication: ML-KEM-768, Post-Quantum\n\"decryption\": \"%v\"\n\"encryption\": \"%v\"\n", decryptionPQ, encryptionPQ)
	
	return nil
}

func generateDotConfig(fields ...string) string {
	return strings.Join(fields, ".")
}
