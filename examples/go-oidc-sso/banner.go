package main

import (
	"fmt"
	"strings"
)

func printStartupBanner(cfg Config, addr string) {
	fmt.Println()
	fmt.Println("\033[1;36m==============================================\033[0m")
	fmt.Println("\033[1;36m   Go OIDC SSO Demo – How to Test This App\033[0m")
	fmt.Println("\033[1;36m==============================================\033[0m")

	fmt.Println("\n\033[1mEnvironment:\033[0m")
	fmt.Printf("  OIDC Issuer:      %s\n", cfg.Issuer)
	fmt.Printf("  Client ID:        %s\n", cfg.ClientID)
	fmt.Printf("  Base URL:         %s\n", cfg.BaseURL)
	fmt.Printf("  Listening on:     http://localhost%s\n", addr)

	fmt.Println("\n\033[1mTest Flow:\033[0m")
	fmt.Println("  1. Open the app in your browser:")
	fmt.Printf("       \033[32m%s/\033[0m\n", addr)
	fmt.Println("  2. Click “/login” to start the OIDC login flow")
	fmt.Println("  3. Authenticate at your OIDC provider")
	fmt.Println("  4. You will be redirected back to:")
	fmt.Printf("       \033[32m%s/oidc/callback\033[0m\n", cfg.BaseURL)
	fmt.Println("  5. After login, visit:")
	fmt.Println("       \033[32m/protected\033[0m to verify session handling")

	fmt.Println("\n\033[1mEndpoints:\033[0m")
	fmt.Println("  GET /              – Home")
	fmt.Println("  GET /login         – Start OIDC login")
	fmt.Println("  GET /logout        – Clear session")
	fmt.Println("  GET /protected     – Requires session")

	// Helpful warning for common mistakes
	if strings.HasSuffix(cfg.Issuer, "/") {
		fmt.Println("\n\033[33mWARNING:\033[0m Issuer ends with a trailing slash.")
		fmt.Println("         OIDC discovery may fail unless the provider returns the same value.")
	}

	fmt.Println("\n\033[1;36mReady.\033[0m\n")
}
