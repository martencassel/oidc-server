package tokens

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

func GenerateDummyIDToken(clientID, subject string) string {
	header := map[string]string{
		"alg": "none",
		"typ": "JWT",
	}

	payload := map[string]interface{}{
		"iss":   "http://localhost:8080",
		"sub":   subject,
		"aud":   clientID,
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"email": "user@example.com",
	}

	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)

	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + "."
}
