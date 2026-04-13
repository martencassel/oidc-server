package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

const sessionCookieName = "app_session"

type Session struct {
	Subject string `json:"sub"`
	Email   string `json:"email,omitempty"`
	Name    string `json:"name,omitempty"`
}

func sign(data, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write(data)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func setSession(w http.ResponseWriter, cfg Config, s Session) error {
	payload, err := json.Marshal(s)
	if err != nil {
		return err
	}
	sig := sign(payload, []byte(cfg.CookieSecret))
	value := base64.RawURLEncoding.EncodeToString(payload) + "." + sig

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // true in production with HTTPS
	})
	return nil
}

func getSession(r *http.Request, cfg Config) (*Session, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, err
	}

	parts := []byte(c.Value)
	dot := -1
	for i, b := range parts {
		if b == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return nil, http.ErrNoCookie
	}

	payloadEnc := parts[:dot]
	sigEnc := parts[dot+1:]

	payload, err := base64.RawURLEncoding.DecodeString(string(payloadEnc))
	if err != nil {
		return nil, err
	}
	expectedSig := sign(payload, []byte(cfg.CookieSecret))
	if expectedSig != string(sigEnc) {
		return nil, http.ErrNoCookie
	}

	var s Session
	if err := json.Unmarshal(payload, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}
