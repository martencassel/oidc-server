package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/martencassel/oidc-server/internal/authorization"
	"github.com/martencassel/oidc-server/internal/client"
	"github.com/martencassel/oidc-server/internal/config"
	"github.com/martencassel/oidc-server/internal/tokens"
)

// TokenHandler handles the token exchange process for the OIDC server
type TokenHandler struct {
	config    *config.AppConfig
	clients   client.ClientStoreInterface
	codeStore authorization.AuthorizationCodeStoreInterface
}

// NewTokenHandler creates a new instance of TokenHandler
func NewTokenHandler(config *config.AppConfig, clients client.ClientStoreInterface, codeStore authorization.AuthorizationCodeStoreInterface) *TokenHandler {
	return &TokenHandler{
		config:    config,
		clients:   clients,
		codeStore: codeStore,
	}
}

// RegisterRoutes registers the routes for the token handler
func RegisterRoutes(r *gin.Engine, tokenHandler *TokenHandler) {
	r.GET("/.well-known/openid-configuration", func(c *gin.Context) {
		tokenHandler.HandleOidcDiscovery(c)
	})
	r.GET("/oauth2/token", func(c *gin.Context) {
		tokenHandler.HandleGetToken(c)
	})
	r.POST("/oauth2/token", func(c *gin.Context) {
		tokenHandler.HandlePostToken(c)
	})
}

// HandleOidcDiscovery handles the OIDC discovery endpoint
func (h *TokenHandler) HandleOidcDiscovery(c *gin.Context) {
	c.JSON(200, gin.H{
		"issuer":                                h.config.PublicURL,
		"authorization_endpoint":                h.config.PublicURL + "/oauth2/authorize",
		"token_endpoint":                        h.config.PublicURL + "/oauth2/token",
		"response_types_supported":              []string{"code"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
	})
}

// HandleGetToken handles the authorization code request
func (h *TokenHandler) HandleGetToken(c *gin.Context) {
	var authReq authorization.AuthorizationRequest
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
	if !h.clients.ValidateClient(authReq.ClientID, "secret123") {
		c.JSON(401, gin.H{
			"error": "unauthorized_client",
		})
		return
	}
	code := h.codeStore.AddCode(authReq.State)
	c.Redirect(302, authReq.RedirectURI+"?code="+code+"&state="+authReq.State)
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

	// In a real implementation, you would validate the authorization code and client credentials here.
	c.JSON(200, gin.H{
		"access_token": "dummy_access_token",
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}
