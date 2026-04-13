package jwk

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

func base64urlUInt(b *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(b.Bytes())
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func RSAtoJWK(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: "RSA",
		Kid: kid,
		Alg: "RS256",
		Use: "sig",
		N:   base64urlUInt(pub.N),
		E:   base64urlUInt(big.NewInt(int64(pub.E))),
	}
}

func JWKS(keys []JWK) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"keys": keys,
	})
}
