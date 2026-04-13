package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/martencassel/oidc-server/internal/client"
)

type APIHandler struct {
	clients client.ClientStoreInterface
}

// NewAPIHandler creates a new instance of APIHandler
func NewAPIHandler(clients client.ClientStoreInterface) *APIHandler {
	return &APIHandler{
		clients: clients,
	}
}

// RegisterRoutes registers the routes for the API handler
func (h *APIHandler) RegisterRoutes(r *gin.Engine) {
	// Example: r.GET("/api/some-endpoint", h.SomeEndpoint)
	r.GET("/api/clients", h.GetClients)
}

// GetClients is an example API endpoint that returns a list of clients
func (h *APIHandler) GetClients(c *gin.Context) {
	clients := h.clients.ListClients()
	c.JSON(200, gin.H{
		"clients": clients,
	})
}
