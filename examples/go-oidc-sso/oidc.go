package main

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDC struct {
	Provider    *oidc.Provider
	Verifier    *oidc.IDTokenVerifier
	OAuth2      *oauth2.Config
	RedirectURL string
}

func newOIDC(ctx context.Context, cfg Config) (*OIDC, error) {
	httpClient := newLoggedHTTPClient()
	ctx = oidc.ClientContext(ctx, httpClient)
	
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}

	oidcConfig := &oidc.Config{
		ClientID: cfg.ClientID,
	}

	verifier := provider.Verifier(oidcConfig)

	redirectURL := cfg.BaseURL + "/oidc/callback"

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return &OIDC{
		Provider:    provider,
		Verifier:    verifier,
		OAuth2:      oauth2Config,
		RedirectURL: redirectURL,
	}, nil
}
