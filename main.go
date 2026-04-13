package main

import (
	"github.com/gin-gonic/gin"
	"github.com/martencassel/oidc-server/internal/authorization"
	"github.com/martencassel/oidc-server/internal/client"
	"github.com/martencassel/oidc-server/internal/config"
	"github.com/martencassel/oidc-server/internal/handler"
	"github.com/martencassel/oidc-server/internal/middleware"
)

func main() {
	appConfig := config.NewAppConfig("http://localhost:8080")
	codeStore := authorization.NewAuthorizationCodeStore()
	clients := client.NewClientStore()
	clients.AddClient(client.Client{
		ID:     "client1",
		Secret: "P@ssw0rd",
	})
	r := gin.Default()
	r.Use(middleware.RequestResponseLogger())
	tokenHandler := handler.NewTokenHandler(appConfig, clients, codeStore)
	handler.RegisterRoutes(r, tokenHandler)
	r.Run(":8080")
}
