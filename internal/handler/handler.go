package handler

import (
	"fmt"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/martencassel/oidc-server/internal/authorization"
	"github.com/martencassel/oidc-server/internal/client"
	"github.com/martencassel/oidc-server/internal/config"
	"github.com/martencassel/oidc-server/internal/jwk"
	"github.com/martencassel/oidc-server/internal/session"
	"github.com/martencassel/oidc-server/internal/tokens"
	log "github.com/sirupsen/logrus"
)

// TokenHandler handles the token exchange process for the OIDC server
type TokenHandler struct {
	sessionStore *session.Store
	config       *config.AppConfig
	clients      client.ClientStoreInterface
	codeStore    authorization.AuthorizationCodeStoreInterface
}

// NewTokenHandler creates a new instance of TokenHandler
func NewTokenHandler(sessionStore *session.Store, config *config.AppConfig, clients client.ClientStoreInterface, codeStore authorization.AuthorizationCodeStoreInterface) *TokenHandler {
	return &TokenHandler{
		sessionStore: sessionStore,
		config:       config,
		clients:      clients,
		codeStore:    codeStore,
	}
}

// RegisterRoutes registers the routes for the token handler
func RegisterRoutes(r *gin.Engine, cfg config.AppConfig, tokenHandler *TokenHandler) {
	r.GET("/.well-known/openid-configuration", func(c *gin.Context) {
		tokenHandler.HandleOidcDiscovery(c)
	})
	r.GET("/oauth2/authorize", func(c *gin.Context) {
		tokenHandler.HandleAuthorize(c)
	})
	r.GET("/oauth2/token", func(c *gin.Context) {
		tokenHandler.HandleGetToken(c)
	})
	r.POST("/oauth2/token", func(c *gin.Context) {
		tokenHandler.HandlePostToken(c)
	})

	r.GET("/.well-known/jwks.json", func(c *gin.Context) {
		if cfg.PublicKey == nil {
			c.JSON(500, gin.H{
				"error": "server_error",
			})
			return
		}
		if cfg.KeyID == "" {
			c.JSON(500, gin.H{
				"error": "server_error",
			})
			return
		}
		jwk_ := jwk.RSAtoJWK(cfg.PublicKey, cfg.KeyID)
		data, _ := jwk.JWKS([]jwk.JWK{jwk_})
		c.Data(200, "application/json", data)
	})

}

// HandleOidcDiscovery handles the OIDC discovery endpoint
func (h *TokenHandler) HandleOidcDiscovery(c *gin.Context) {
	c.JSON(200, gin.H{
		"issuer":                                h.config.PublicURL,
		"authorization_endpoint":                h.config.PublicURL + "/oauth2/authorize",
		"token_endpoint":                        h.config.PublicURL + "/oauth2/token",
		"jwks_uri":                              h.config.PublicURL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
	})
}

func (h *TokenHandler) HandleGetToken(c *gin.Context) {
	c.JSON(400, gin.H{
		"error": "invalid_request",
	})
}

func (h *TokenHandler) redirectToLogin(c *gin.Context) {
	returnTo := c.Request.URL.String()
	loginURL := "/login?return_to=" + url.QueryEscape(returnTo)
	c.Redirect(302, loginURL)
}

// HandleAuthorize handles the authorization request
func (h *TokenHandler) HandleAuthorize(c *gin.Context) {
	// 1. Check session cookie
	cookie, err := c.Request.Cookie("sid")
	if err != nil {
		// Not logged in → redirect to login
		h.redirectToLogin(c)
		return
	}

	sess, ok := h.sessionStore.Get(cookie.Value)
	if !ok {
		h.redirectToLogin(c)
		return
	}

	// 2. User is authenticated → issue authorization code
	var authReq authorization.AuthorizationRequest
	err = c.ShouldBindQuery(&authReq)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "invalid_request",
		})
		return
	}
	code := h.codeStore.AddCode(authReq.State, sess.Subject)

	// 3. Redirect back to client
	redirect := fmt.Sprintf("%s?code=%s&state=%s", authReq.RedirectURI, code, authReq.State)
	c.Redirect(302, redirect)

	log.Infof("Received authorization request: %+v", authReq)
	if authReq.ResponseType != "code" {
		c.JSON(400, gin.H{
			"error": "unsupported_response_type",
		})
		return
	}
	redirect = fmt.Sprintf("%s?code=%s&state=%s", authReq.RedirectURI, code, authReq.State)
	c.Redirect(302, redirect)
}

// HandlePostToken handles the token exchange request
func (h *TokenHandler) HandlePostToken(c *gin.Context) {
	var tokenReq tokens.TokenRequest
	err := c.ShouldBind(&tokenReq)
	if err != nil || !tokenReq.IsValid() {
		c.JSON(400, gin.H{
			"error": "invalid_request",
		})
		return
	}

	log.Infof("Received token request: %+v", tokenReq)
	// Validate the authorization code and client credentials
	if !h.codeStore.ValidateCode(tokenReq.Code, "") {
		c.JSON(400, gin.H{
			"error": "invalid_grant",
		})
		return
	}
	if !h.clients.ValidateClient(tokenReq.ClientID, tokenReq.ClientSecret) {
		c.JSON(401, gin.H{
			"error": "unauthorized_client",
		})
		return
	}

	// Check if the code is expired
	authCode, exists := h.codeStore.GetCode(tokenReq.Code)
	if !exists || authCode.IsExpired() {
		c.JSON(400, gin.H{
			"error": "invalid_grant",
		})
		return
	}

	// Remove the code after successful validation to prevent reuse
	h.codeStore.RemoveCode(tokenReq.Code)

	idToken, err := h.generateIDToken(authCode.Subject, tokenReq.ClientID)
	if err != nil {
		c.JSON(500, gin.H{
			"error": "server_error",
		})
		return
	}
	c.JSON(200, gin.H{
		"access_token": "dummy_access_token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})

}

func (h *TokenHandler) generateIDToken(subject, clientID string) (string, error) {
	claims := jwt.MapClaims{
		"iss":   h.config.PublicURL,
		"sub":   subject,
		"aud":   clientID,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"email": "user@example.com",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = h.config.KeyID

	return token.SignedString(h.config.PrivateKey)
}
