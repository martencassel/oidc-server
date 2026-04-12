package tokens

import (
	"sync"
	"time"
)

// SiningKeyManager defines the interface for managing signing keys
type SiningKeyManager interface {
	GetSigningKey() (string, error)
}

// TokenService defines the interface for issuing tokens
type SigningKeyRotator interface {
	RotateSigningKey() error
}

// KeyStoreInMemory is an in-memory implementation of the SiningKeyManager and SigningKeyRotator interfaces
type KeyStoreInMemory struct {
	currentKey string
	mu         sync.RWMutex
}

// NewKeyStoreInMemory creates a new instance of KeyStoreInMemory with an initial signing key
func NewKeyStoreInMemory() *KeyStoreInMemory {
	return &KeyStoreInMemory{
		currentKey: "initial_signing_key",
	}
}

// GetSigningKey returns the current signing key
func (k *KeyStoreInMemory) GetSigningKey() (string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.currentKey, nil
}

// RotateSigningKey generates a new signing key and updates the current key
func (k *KeyStoreInMemory) RotateSigningKey() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.currentKey = "rotated_signing_key_" + time.Now().Format("20060102150405")
	return nil
}
