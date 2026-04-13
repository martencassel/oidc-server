package users

import (
	"sync"

	"github.com/martencassel/oidc-server/internal/client"
)

type User struct {
	Subject  string
	Email    string
	Name     string
	Groups   []string
	Password string
}

type UserStore interface {
	Authenticate(username, password string) (User, bool)
	GetUserBySubject(sub string) (User, bool)
	AddUser(user User)
	Clear()
	GetClaims(sub string, scopes []string, client client.Client) (map[string]interface{}, bool)
}

type InMemoryUserStore struct {
	mu    sync.RWMutex
	users map[string]User
}

func NewInMemoryUserStore() *InMemoryUserStore {
	return &InMemoryUserStore{
		users: make(map[string]User),
	}
}
func (s *InMemoryUserStore) AddUser(user User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.Subject] = user
}

func (s *InMemoryUserStore) Authenticate(username, password string) (User, bool) {

	if username == "" || password == "" {
		return User{}, false
	}

	// Lookup user by username (in this example, we use the username as the subject)
	s.mu.RLock()
	user, exists := s.users[username]
	s.mu.RUnlock()

	if !exists {
		return User{}, false
	}
	// Check password (in this example, we use a simple equality check)
	if user.Password != password {
		return User{}, false
	}
	return user, true
}

func (s *InMemoryUserStore) GetUserBySubject(sub string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, exists := s.users[sub]
	return user, exists
}

func (s *InMemoryUserStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = make(map[string]User)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func filterByClientPolicy(claims map[string]interface{}, client client.Client) map[string]interface{} {
	filtered := make(map[string]interface{})
	for _, claim := range client.AllowedClaims {
		if value, exists := claims[claim]; exists {
			filtered[claim] = value
		}
	}
	return filtered
}

func (s *InMemoryUserStore) GetClaims(sub string, scopes []string, client client.Client) (map[string]interface{}, bool) {
	user, exists := s.GetUserBySubject(sub)
	if !exists {
		return nil, false
	}

	// 1. Base claims
	claims := map[string]interface{}{
		"sub": user.Subject,
	}

	// 2. Scope-based claims
	if contains(scopes, "email") {
		claims["email"] = user.Email
	}
	if contains(scopes, "profile") {
		claims["name"] = user.Name
	}
	if contains(scopes, "groups") {
		claims["groups"] = user.Groups
	}

	// 3. Client-specific claim filtering
	claims = filterByClientPolicy(claims, client)

	return claims, true
}
