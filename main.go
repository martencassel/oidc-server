package main

import (
	"github.com/gin-gonic/gin"
	"github.com/martencassel/oidc-server/internal/authorization"
	"github.com/martencassel/oidc-server/internal/client"
	"github.com/martencassel/oidc-server/internal/config"
	"github.com/martencassel/oidc-server/internal/handler"
)

func main() {
	appConfig := config.NewAppConfig("http://localhost:8080")
	codeStore := authorization.NewAuthorizationCodeStore()
	clients := client.NewClientStore()
	clients.AddClient(client.Client{
		ID:     "client123",
		Secret: "secret123",
	})
	r := gin.Default()
	tokenHandler := handler.NewTokenHandler(appConfig, clients, codeStore)
	handler.RegisterRoutes(r, tokenHandler)
	r.Run(":8080")
}
