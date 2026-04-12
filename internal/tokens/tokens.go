package tokens

import (
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IDTokenClaims represents the claims that are included in an ID Token issued by the OIDC server. These claims are based on the OpenID Connect specification and include standard fields such as issuer, subject, audience, expiration time, and issued at time.
type IDTokenClaims struct {
	Issuer   string `json:"iss"` // Required. The issuer identifier for the issuer of the response. This MUST be a URL using the https scheme with no query or fragment components.
	Subject  string `json:"sub"` // Required. The subject identifier. MUST be unique in the context of the issuer and MUST NOT be reassigned. The sub value is a case-sensitive string containing a UUID or other unique identifier.
	Audience string `json:"aud"` // Required. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY also contain identifiers for other audiences. In the general case, the aud value is an array of case-sensitive strings. In the common special case when there is one audience, the aud value MAY be a single case-sensitive string.
	Expiry   int64  `json:"exp"` // Required. Expiration time on or after which the ID Token MUST NOT be accepted for processing. The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value. Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.
	IssuedAt int64  `json:"iat"` // Required. Time at which the JWT was issued. Its value is a JSON number representing the number of seconds from 1970-01-01T00:00:00Z UTC until the date/time.
}

// TokenService defines the interface for issuing and validating tokens in the OIDC server.
type TokenService interface {
	IssueToken(claims IDTokenClaims) (string, error)
}

// TokenItem represents a token along with its metadata, such as the associated client ID and expiration time.
type TokenItem struct {
	Token     *jwt.Token
	Signature string
	ClientID  string
	ExpiresAt time.Time
}

// IsExpired checks if the token has expired based on the current time and the ExpiresAt field
func (t TokenItem) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// VerifySignature verifies the token's signature using the provided signing key
func (t TokenItem) VerifySignature(signingKey string) bool {
	parsedToken, err := jwt.Parse(t.Signature, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(signingKey), nil
	})
	if err != nil {
		return false
	}
	return parsedToken.Valid
}

// tokenServiceImpl is an implementation of the TokenService interface that manages tokens in memory and uses a signing key manager for signing and validating tokens.
type tokenServiceImpl struct {
	mu                sync.Mutex
	tokens            map[string]*TokenItem
	signingKeyManager SiningKeyManager
}

// NewTokenServiceImpl creates a new instance of tokenServiceImpl with the provided signing key manager
func NewTokenServiceImpl(signingKeyManager SiningKeyManager) *tokenServiceImpl {
	return &tokenServiceImpl{
		tokens:            make(map[string]*TokenItem),
		signingKeyManager: signingKeyManager,
	}
}

// IssueToken generates a new JWT token based on the provided claims and stores it in memory
func (s *tokenServiceImpl) IssueToken(claims IDTokenClaims) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": claims.Issuer,
		"sub": claims.Subject,
		"aud": claims.Audience,
		"exp": claims.Expiry,
		"iat": claims.IssuedAt,
	})
	signingKey, err := s.signingKeyManager.GetSigningKey()
	if err != nil {
		return "", err
	}
	tokenString, err := token.SignedString([]byte(signingKey))
	if err != nil {
		return "", err
	}
	s.tokens[tokenString] = &TokenItem{
		Token:     token,
		Signature: tokenString,
		ClientID:  claims.Audience,
		ExpiresAt: time.Unix(claims.Expiry, 0),
	}
	return tokenString, nil
}

// ValidateToken checks if the provided token string is valid, not expired, and has a valid signature. It returns the associated client ID if the token is valid.
func (s *tokenServiceImpl) ValidateToken(tokenString string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tokenItem, exists := s.tokens[tokenString]
	if !exists || tokenItem.IsExpired() {
		return "", jwt.ErrTokenExpired
	}
	signingKey, err := s.signingKeyManager.GetSigningKey()
	if err != nil {
		return "", err
	}
	if !tokenItem.VerifySignature(signingKey) {
		return "", jwt.ErrSignatureInvalid
	}
	return tokenItem.ClientID, nil
}

type TokenIssuer interface {
	IssueToken(clientID string, code string) (string, error)
}

type TokenValidator interface {
	ValidateToken(token string) (string, error)
}

type tokenService struct {
	mu     sync.Mutex
	tokens map[string]string // token -> clientID
}

type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func NewTokenService() *tokenService {
	return &tokenService{
		tokens: make(map[string]string),
	}
}
