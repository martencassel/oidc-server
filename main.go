package main

import (
	"math/rand"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type SiningKeyManager interface {
	GetSigningKey() (string, error)
}

type SigningKeyRotator interface {
	RotateSigningKey() error
}

type KeyStoreInMemory struct {
	currentKey string
	mu         sync.RWMutex
}

func NewKeyStoreInMemory() *KeyStoreInMemory {
	return &KeyStoreInMemory{
		currentKey: "initial_signing_key",
	}
}

func (k *KeyStoreInMemory) GetSigningKey() (string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.currentKey, nil
}

func (k *KeyStoreInMemory) RotateSigningKey() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.currentKey = "rotated_signing_key_" + time.Now().Format("20060102150405")
	return nil
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

type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required"`
	Code         string `form:"code" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required,url"`
	ClientID     string `form:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret" binding:"required"`
}

func (r TokenRequest) IsValid() bool {
	return r.GrantType == "authorization_code" &&
		r.Code != "" &&
		r.RedirectURI != "" &&
		r.ClientID != "" &&
		r.ClientSecret != ""
}

type AuthorizationCode struct {
	Code      string
	State     string
	IssuedAt  time.Time
	ExpiresIn time.Duration
}

func (c AuthorizationCode) IsValid() bool {
	return c.Code != "" && c.State != "" && !c.IsExpired()
}

func (c AuthorizationCode) IsExpired() bool {
	return time.Since(c.IssuedAt) > c.ExpiresIn
}

type AuthorizationCodeStore struct {
	codes map[string]AuthorizationCode
	mu    sync.RWMutex
}

func GenerateAuthorizationCode() string {
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

func NewAuthorizationCodeStore() *AuthorizationCodeStore {
	return &AuthorizationCodeStore{
		codes: make(map[string]AuthorizationCode),
	}
}

func (s *AuthorizationCodeStore) ClearExpiredCodes() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for code, authCode := range s.codes {
		if authCode.IsExpired() {
			delete(s.codes, code)
		}
	}
}

func (s *AuthorizationCodeStore) RemoveCode(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, code)
}

func (s *AuthorizationCodeStore) AddCode(state string) string {
	code := GenerateAuthorizationCode()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = AuthorizationCode{
		Code:      code,
		State:     state,
		IssuedAt:  time.Now(),
		ExpiresIn: 5 * time.Minute,
	}
	return code
}

func (s *AuthorizationCodeStore) GetCode(code string) (AuthorizationCode, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	authCode, exists := s.codes[code]
	return authCode, exists
}

func (s *AuthorizationCodeStore) ValidateCode(code, state string) bool {
	authCode, exists := s.GetCode(code)
	if !exists {
		return false
	}
	return authCode.State == state
}

type Client struct {
	ID     string
	Secret string
}

type ClientStore struct {
	clients map[string]Client
	mu      sync.RWMutex
}

func NewClientStore() *ClientStore {
	return &ClientStore{
		clients: make(map[string]Client),
	}
}

func (s *ClientStore) AddClient(client Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[client.ID] = client
}

func (s *ClientStore) GetClient(id string) (Client, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, exists := s.clients[id]
	return client, exists
}

func (s *ClientStore) ValidateClient(id, secret string) bool {
	client, exists := s.GetClient(id)
	if !exists {
		return false
	}
	return client.Secret == secret
}

type AuthorizationRequest struct {
	ResponseType string `form:"response_type" binding:"required"`
	ClientID     string `form:"client_id" binding:"required"`
	State        string `form:"state" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required,url"`
}

type AppConfig struct {
	PublicURL string
}

func NewAppConfig(publicUrl string) *AppConfig {
	return &AppConfig{
		PublicURL: publicUrl,
	}
}

func main() {

	appConfig := NewAppConfig("http://localhost:8080")

	codeStore := NewAuthorizationCodeStore()
	clients := NewClientStore()
	clients.AddClient(Client{
		ID:     "client123",
		Secret: "secret123",
	})
	r := gin.Default()
	r.GET("/.well-known/openid-configuration", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"issuer":                                appConfig.PublicURL,
			"authorization_endpoint":                appConfig.PublicURL + "/oauth2/authorize",
			"token_endpoint":                        appConfig.PublicURL + "/oauth2/token",
			"response_types_supported":              []string{"code"},
			"scopes_supported":                      []string{"openid", "profile", "email"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		})
	})
	r.GET("/oauth2/authorize", func(c *gin.Context) {
		var authReq AuthorizationRequest
		err := c.ShouldBindQuery(&authReq)
		if err != nil {
			c.JSON(400, gin.H{
				"error": "invalid_request",
			})
			return
		}
		if authReq.ResponseType != "code" {
			c.JSON(400, gin.H{
				"error": "unsupported_response_type",
			})
			return
		}
		if !clients.ValidateClient(authReq.ClientID, "secret123") {
			c.JSON(401, gin.H{
				"error": "unauthorized_client",
			})
			return
		}
		code := codeStore.AddCode(authReq.State)
		c.Redirect(302, authReq.RedirectURI+"?code="+code+"&state="+authReq.State)
	})

	// Back channel endpoint for token exchange (not fully implemented)
	r.POST("/oauth2/token", func(c *gin.Context) {
		var tokenReq TokenRequest
		err := c.ShouldBind(&tokenReq)
		if err != nil || !tokenReq.IsValid() {
			c.JSON(400, gin.H{
				"error": "invalid_request",
			})
			return
		}

		// Validate the authorization code and client credentials
		if !codeStore.ValidateCode(tokenReq.Code, "") {
			c.JSON(400, gin.H{
				"error": "invalid_grant",
			})
			return
		}
		if !clients.ValidateClient(tokenReq.ClientID, tokenReq.ClientSecret) {
			c.JSON(401, gin.H{
				"error": "unauthorized_client",
			})
			return
		}

		// Check if the code is expired
		authCode, exists := codeStore.GetCode(tokenReq.Code)
		if !exists || authCode.IsExpired() {
			c.JSON(400, gin.H{
				"error": "invalid_grant",
			})
			return
		}

		// Remove the code after successful validation to prevent reuse
		codeStore.RemoveCode(tokenReq.Code)

		// In a real implementation, you would validate the authorization code and client credentials here.
		c.JSON(200, gin.H{
			"access_token": "dummy_access_token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	r.Run(":8080")

}
