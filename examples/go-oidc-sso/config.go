package main

import "os"

type Config struct {
	ClientID              string
	ClientSecret          string
	Issuer                string
	BaseURL               string // e.g. "http://localhost:8080"
	CookieSecret          string // for signing session cookie
	PostLogoutRedirectURI string // optional, e.g. "http://localhost:8080"
	LogoutEndpoint        string // optional, e.g. "http://localhost:8080/logout"
}

func loadConfig() Config {
	return Config{
		ClientID:              os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret:          os.Getenv("OIDC_CLIENT_SECRET"),
		Issuer:                os.Getenv("OIDC_ISSUER"),
		BaseURL:               os.Getenv("APP_BASE_URL"),
		CookieSecret:          os.Getenv("COOKIE_SECRET"),
		PostLogoutRedirectURI: os.Getenv("POST_LOGOUT_REDIRECT_URI"),
		LogoutEndpoint:        os.Getenv("LOGOUT_ENDPOINT"),
	}
}
