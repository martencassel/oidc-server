package main

import (
	"github.com/gin-gonic/gin"
	"github.com/martencassel/oidc-server/internal/authorization"
	"github.com/martencassel/oidc-server/internal/client"
	"github.com/martencassel/oidc-server/internal/config"
	"github.com/martencassel/oidc-server/internal/handler"
	"github.com/martencassel/oidc-server/internal/middleware"
	"github.com/martencassel/oidc-server/internal/session"
	"github.com/martencassel/oidc-server/internal/users"
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
		ID:            "client1",
		Secret:        "P@ssw0rd!",
		RedirectURIs:  []string{"http://localhost:9090/oidc/callback"},
		AllowedScopes: []string{"openid", "profile", "email"},
		AllowedClaims: []string{"sub", "name", "email"},
	})
	r := gin.Default()
	r.LoadHTMLGlob("templates/*")
	r.Use(middleware.RequestResponseLogger())
	sessions := session.NewStore()
	userStore := users.NewInMemoryUserStore()
	u := users.User{
		Subject:  "user1",
		Email:    "user1@gmail.com",
		Name:     "User One",
		Groups:   []string{"group1", "group2"},
		Password: "P@ssw0rd!",
	}
	userStore.AddUser(u)
	apiHandler := handler.NewAPIHandler(clients)
	apiHandler.RegisterRoutes(r)
	loginHandler := handler.NewLoginHandler(userStore, sessions)
	loginHandler.RegisterRoutes(r)
	tokenHandler := handler.NewTokenHandler(sessions, appConfig, clients, codeStore)
	handler.RegisterRoutes(r, *appConfig, tokenHandler)
	r.Run(":8080")
}
