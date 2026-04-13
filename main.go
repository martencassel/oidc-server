package main

import (
	"github.com/gin-gonic/gin"
	"github.com/martencassel/oidc-server/internal/authorization"
	"github.com/martencassel/oidc-server/internal/client"
	"github.com/martencassel/oidc-server/internal/config"
	"github.com/martencassel/oidc-server/internal/handler"
	"github.com/martencassel/oidc-server/internal/middleware"
	"github.com/martencassel/oidc-server/internal/session"
)

func main() {
	privKey, pubKey, err := config.LoadKeys()
	if err != nil {
		panic(err)
	}
	if privKey == nil || pubKey == nil {
		panic("failed to load keys")
	}
	appConfig := config.NewAppConfig("http://localhost:8080", "key1", privKey, pubKey)
	codeStore := authorization.NewAuthorizationCodeStore()
	clients := client.NewClientStore()
	clients.AddClient(client.Client{
		ID:     "client1",
		Secret: "P@ssw0rd!",
	})
	r := gin.Default()
	r.Use(middleware.RequestResponseLogger())
	sessions := session.NewStore()
	tokenHandler := handler.NewTokenHandler(sessions, appConfig, clients, codeStore)
	handler.RegisterRoutes(r, *appConfig, tokenHandler)
	r.Run(":8080")
}
