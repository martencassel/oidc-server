package users

import (
	"testing"

	"github.com/martencassel/oidc-server/internal/client"
)

func TestUsers(t *testing.T) {

	// 1. User has attributes, configured by admin.
	userStore := NewInMemoryUserStore()
	userStore.AddUser(User{
		Subject: "user1",
		Email:   "user1@gmail.com",
		Name:    "User One",
		Groups:  []string{"group1", "group2"},
	})

	// 2. Client policy, configured by admin.
	clientStore := client.NewClientStore()
	clientStore.AddClient(client.Client{
		ID:            "client1",
		Secret:        "P@ssw0rd!",
		AllowedScopes: []string{"openid", "profile", "email"},
		AllowedClaims: []string{"sub", "email", "name"},
	})

	// 3. Runtime scope request
	//
	// 3.1 Controlled by the client at login:
	//
	scopeRequest := []string{"openid", "email"}

	// 3.2 Controlled by the user at login:
	//
	// scopeRequest := []string{"openid", "email", "profile"}

	// 4. Claims are filtered by client policy and scope request.
	claims, exists := userStore.GetClaims("user1", scopeRequest, client.Client{
		ID:            "client1",
		Secret:        "P@ssw0rd!",
		AllowedScopes: []string{"openid", "profile", "email"},
		AllowedClaims: []string{"sub", "email", "name"},
	})
	if !exists {
		t.Fatalf("Expected claims to exist for user1")
	}
	if claims["sub"] != "user1" {
		t.Errorf("Expected sub claim to be 'user1', got '%v'", claims["sub"])
	}
	if claims["email"] != "" {
		t.Errorf("Expected email claim to be filtered out, got '%v'", claims["email"])
	}
	if claims["name"] != "" {
		t.Errorf("Expected name claim to be filtered out, got '%v'", claims["name"])
	}

}
