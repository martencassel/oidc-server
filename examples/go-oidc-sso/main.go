package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type app struct {
	cfg  Config
	oidc *OIDC
}

func main() {
	cfg := loadConfig()
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.Issuer == "" || cfg.BaseURL == "" || cfg.CookieSecret == "" {
		log.Fatal("missing required config (set OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_ISSUER, APP_BASE_URL, COOKIE_SECRET)")
	}
	ctx := context.Background()

	oidcClient, err := newOIDC(ctx, cfg)
	if err != nil {
		log.Fatalf("init oidc: %v", err)
	}

	a := &app{
		cfg:  cfg,
		oidc: oidcClient,
	}

	printStartupBanner(cfg, cfg.BaseURL)

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.indexHandler)
	mux.HandleFunc("/login", a.loginHandler)
	mux.HandleFunc("/logout", a.logoutHandler)
	mux.HandleFunc("/oidc/callback", a.callbackHandler)
	mux.Handle("/protected", a.requireSession(http.HandlerFunc(a.protectedHandler)))

	addr := ":9090"
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func (a *app) indexHandler(w http.ResponseWriter, r *http.Request) {
	sess, _ := getSession(r, a.cfg)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if sess != nil {
		fmt.Fprintf(w, `
            <html>
            <body style="font-family: sans-serif;">
                <h2>Hello %s</h2>
                <p>Subject: %s</p>
                <p><a href="/protected">Go to protected page</a></p>
                <form action="/logout" method="GET">
                    <button style="padding: 8px 16px;">Logout</button>
                </form>
            </body>
            </html>
        `, sess.Email, sess.Subject)
		return
	}

	// Not logged in → show login button
	fmt.Fprint(w, `
        <html>
        <body style="font-family: sans-serif;">
            <h2>You are not logged in</h2>
            <form action="/login" method="GET">
                <button style="padding: 10px 20px; font-size: 16px;">
                    Login with OIDC
                </button>
            </form>
        </body>
        </html>
    `)
}

func (a *app) loginHandler(w http.ResponseWriter, r *http.Request) {
	state := "some-random-state" // TODO: real CSRF-safe state
	url := a.oidc.OAuth2.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

func (a *app) callbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ctx = oidc.ClientContext(ctx, newLoggedHTTPClient())

	if errStr := r.URL.Query().Get("error"); errStr != "" {
		http.Error(w, "oidc error: "+errStr, http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	// TODO: validate state

	oauth2Token, err := a.oidc.OAuth2.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusBadRequest)
		return
	}

	idToken, err := a.oidc.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "id_token verify failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	var claims struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "claims parse failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := setSession(w, a.cfg, Session{
		Subject: idToken.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
	}); err != nil {
		http.Error(w, "set session failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request, cfg Config) {
	// 1. Load session (may be nil if user already logged out)
	sess, _ := getSession(r, cfg)

	// 2. Extract ID Token for id_token_hint
	var idToken string
	if sess != nil {
		idToken = sess.IDToken
	}

	// 3. Clear local session
	clearSession(w)

	// 4. Build OP logout URL
	q := url.Values{}
	if idToken != "" {
		q.Set("id_token_hint", idToken)
	}
	q.Set("post_logout_redirect_uri", cfg.PostLogoutRedirectURI)

	// Optional: state for CSRF protection
	state := generateRandomString(16)
	q.Set("state", state)

	logoutURL := cfg.LogoutEndpoint + "?" + q.Encode()

	// 5. Redirect user to the OP logout endpoint
	http.Redirect(w, r, logoutURL, http.StatusFound)
}

func generateRandomString(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a *app) logoutHandler(w http.ResponseWriter, r *http.Request) {

	clearSession(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *app) protectedHandler(w http.ResponseWriter, r *http.Request) {
	sess, _ := getSession(r, a.cfg)
	fmt.Fprintf(w, "Protected content for %s (sub=%s)\n", sess.Email, sess.Subject)
}

func (a *app) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := getSession(r, a.cfg)
		if err != nil || sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		// optionally put session in context
		next.ServeHTTP(w, r)
	})
}
