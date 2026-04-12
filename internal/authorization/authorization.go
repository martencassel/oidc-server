package authorization

import (
	"math/rand"
	"sync"
	"time"
)

// AuthorizationCode represents an authorization code issued to a client application.
type AuthorizationCode struct {
	Code      string
	State     string
	IssuedAt  time.Time
	ExpiresIn time.Duration
}

// NewAuthorizationCode creates a new AuthorizationCode with the given parameters.
func NewAuthorizationCode(code, state string, issuedAt time.Time, expiresIn time.Duration) AuthorizationCode {
	return AuthorizationCode{
		Code:      code,
		State:     state,
		IssuedAt:  issuedAt,
		ExpiresIn: expiresIn,
	}
}

// IsValid checks if the authorization code is valid (not expired and has a state).
func (c AuthorizationCode) IsValid() bool {
	return c.Code != "" && c.State != "" && !c.IsExpired()
}

// IsExpired checks if the authorization code has expired based on the issued time and expiration duration.
func (c AuthorizationCode) IsExpired() bool {
	return time.Since(c.IssuedAt) > c.ExpiresIn
}

// AuthorizationCodeStoreInterface defines the methods for managing authorization codes.
type AuthorizationCodeStoreInterface interface {
	AddCode(state string) string
	GetCode(code string) (AuthorizationCode, bool)
	ValidateCode(code, state string) bool
	ClearExpiredCodes()
	RemoveCode(code string)
}

// AuthorizationCodeStore is an in-memory store for managing authorization codes.
type AuthorizationCodeStore struct {
	codes map[string]AuthorizationCode
	mu    sync.RWMutex
}

// GenerateAuthorizationCode generates a random string to be used as an authorization code.
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

// NewAuthorizationCodeStore creates a new instance of AuthorizationCodeStore.
func NewAuthorizationCodeStore() *AuthorizationCodeStore {
	return &AuthorizationCodeStore{
		codes: make(map[string]AuthorizationCode),
	}
}

// ClearExpiredCodes removes all expired authorization codes from the store.
func (s *AuthorizationCodeStore) ClearExpiredCodes() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for code, authCode := range s.codes {
		if authCode.IsExpired() {
			delete(s.codes, code)
		}
	}
}

// RemoveCode removes an authorization code from the store.
func (s *AuthorizationCodeStore) RemoveCode(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, code)
}

// AddCode generates a new authorization code for the given state and stores it in the store.
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

// GetCode retrieves an authorization code from the store based on the provided code string.
func (s *AuthorizationCodeStore) GetCode(code string) (AuthorizationCode, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	authCode, exists := s.codes[code]
	return authCode, exists
}

// ValidateCode checks if the provided code exists in the store and if its state matches the provided state.
func (s *AuthorizationCodeStore) ValidateCode(code, state string) bool {
	authCode, exists := s.GetCode(code)
	if !exists {
		return false
	}
	return authCode.State == state
}
