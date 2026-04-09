// Package main provides main functionality for the proxy.
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	// DefaultPrivateKeyPath is the default value for private key path.
	DefaultPrivateKeyPath = "../../test/certs/jwt_test_private.pem"
	// DefaultPublicKeyPath is the default value for public key path.
	DefaultPublicKeyPath  = "../../test/certs/jwt_test_public.pem"
)

// Claims represents a claims.
type Claims struct {
	jwt.RegisteredClaims
	Email  string   `json:"email,omitempty"`
	Name   string   `json:"name,omitempty"`
	Roles  []string `json:"roles,omitempty"`
	UserID string   `json:"user_id,omitempty"`
}

func main() {
	// Command line flags
	algorithm := flag.String("alg", "RS256", "JWT algorithm (RS256, RS384, RS512, HS256)")
	privateKey := flag.String("key", DefaultPrivateKeyPath, "Path to private key file (for RSA)")
	secret := flag.String("secret", "", "HMAC secret (for HS256)")
	subject := flag.String("sub", "user123", "Subject (user ID)")
	issuer := flag.String("iss", "test-issuer", "Issuer")
	audience := flag.String("aud", "test-audience", "Audience")
	email := flag.String("email", "user@example.com", "Email claim")
	name := flag.String("name", "Test User", "Name claim")
	roles := flag.String("roles", "user,admin", "Comma-separated roles")
	userID := flag.String("userid", "user123", "User ID claim")
	expiryHours := flag.Int("exp", 24, "Expiry in hours (0 = no expiry)")
	showKeys := flag.Bool("show-keys", false, "Show public key for verification")
	base64Keys := flag.Bool("base64", false, "Show keys in base64-encoded DER format")

	flag.Parse()

	// Handle show-keys flag
	if *showKeys {
		showPublicKey(*base64Keys)
		return
	}

	// Parse roles
	var rolesList []string
	if *roles != "" {
		// Simple split by comma
		rolesList = []string{}
		current := ""
		for _, c := range *roles {
			if c == ',' {
				if current != "" {
					rolesList = append(rolesList, current)
					current = ""
				}
			} else {
				current += string(c)
			}
		}
		if current != "" {
			rolesList = append(rolesList, current)
		}
	}

	// Create claims
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   *subject,
			Issuer:    *issuer,
			Audience:  jwt.ClaimStrings{*audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		Email:  *email,
		Name:   *name,
		Roles:  rolesList,
		UserID: *userID,
	}

	// Add expiry if specified
	if *expiryHours > 0 {
		claims.ExpiresAt = jwt.NewNumericDate(now.Add(time.Duration(*expiryHours) * time.Hour))
	}

	// Create token based on algorithm
	var token *jwt.Token
	var tokenString string
	var err error

	switch *algorithm {
	case "RS256":
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, err = signWithRSA(token, *privateKey)
	case "RS384":
		token = jwt.NewWithClaims(jwt.SigningMethodRS384, claims)
		tokenString, err = signWithRSA(token, *privateKey)
	case "RS512":
		token = jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
		tokenString, err = signWithRSA(token, *privateKey)
	case "HS256":
		if *secret == "" {
			fmt.Fprintf(os.Stderr, "Error: HMAC secret required for HS256 algorithm (use -secret flag)\n")
			os.Exit(1)
		}
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err = token.SignedString([]byte(*secret))
	default:
		fmt.Fprintf(os.Stderr, "Error: Unsupported algorithm: %s\n", *algorithm)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating token: %v\n", err)
		os.Exit(1)
	}

	// Output token
	fmt.Println("JWT Token Generated Successfully!")
	fmt.Println("================================")
	fmt.Printf("Algorithm: %s\n", *algorithm)
	fmt.Printf("Subject: %s\n", *subject)
	fmt.Printf("Issuer: %s\n", *issuer)
	fmt.Printf("Audience: %s\n", *audience)
	fmt.Printf("Email: %s\n", *email)
	fmt.Printf("Name: %s\n", *name)
	if len(rolesList) > 0 {
		fmt.Printf("Roles: %v\n", rolesList)
	}
	if *expiryHours > 0 {
		fmt.Printf("Expires: %s (in %d hours)\n", claims.ExpiresAt.Time.Format(time.RFC3339), *expiryHours)
	} else {
		fmt.Println("Expires: Never (no expiry set)")
	}
	fmt.Println()
	fmt.Println("Token:")
	fmt.Println(tokenString)
	fmt.Println()
	fmt.Println("Use with Authorization header:")
	fmt.Printf("Authorization: Bearer %s\n", tokenString)
}

func signWithRSA(token *jwt.Token, keyPath string) (string, error) {
	// Read private key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read private key: %w", err)
	}

	// Parse PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block")
	}

	// Parse private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return "", fmt.Errorf("failed to parse private key: %w (PKCS1: %v)", err2, err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("key is not RSA private key")
		}
	}

	// Sign token
	return token.SignedString(privateKey)
}

func showPublicKey(base64Format bool) {
	keyPath := DefaultPublicKeyPath
	if !fileExists(keyPath) {
		// Try alternative path
		keyPath = "../../test/certs/jwt_test_public.pem"
		if !fileExists(keyPath) {
			keyPath = filepath.Join("certs", "jwt_test_public.pem")
		}
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading public key: %v\n", err)
		fmt.Fprintf(os.Stderr, "Tried path: %s\n", keyPath)
		os.Exit(1)
	}

	if base64Format {
		// Parse PEM and convert to base64-encoded DER
		block, _ := pem.Decode(keyData)
		if block == nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to parse PEM block\n")
			os.Exit(1)
		}

		base64Key := base64.StdEncoding.EncodeToString(block.Bytes)
		
		fmt.Println("RSA Public Key (Base64-encoded DER format):")
		fmt.Println("===========================================")
		fmt.Println(base64Key)
		fmt.Println()
		fmt.Println("Use this in your JWT auth config:")
		fmt.Println("{")
		fmt.Println("  \"auth\": {")
		fmt.Println("    \"type\": \"jwt\",")
		fmt.Println("    \"algorithm\": \"RS256\",")
		fmt.Printf("    \"public_key\": \"%s\"\n", base64Key)
		fmt.Println("  }")
		fmt.Println("}")
	} else {
		fmt.Println("RSA Public Key (PEM format):")
		fmt.Println("============================")
		fmt.Print(string(keyData))
		fmt.Println()
		fmt.Println("Use this key for JWT verification in your config.")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

