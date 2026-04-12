package client

import "sync"

// Client represents a client application that can request authorization from the authorization server.
type Client struct {
	ID     string
	Secret string
}

// IsValid checks if the client has a valid ID and secret.
func (c Client) IsValid() bool {
	return c.ID != "" && c.Secret != ""
}

// ClientStoreInterface defines the methods for managing clients in the authorization server.
type ClientStoreInterface interface {
	AddClient(client Client)
	GetClient(id string) (Client, bool)
	ValidateClient(id, secret string) bool
}

// ClientStore is an in-memory store for managing clients in the authorization server.
type ClientStore struct {
	clients map[string]Client
	mu      sync.RWMutex
}

// NewClientStore creates a new ClientStore with an initialized clients map.
func NewClientStore() *ClientStore {
	return &ClientStore{
		clients: make(map[string]Client),
	}
}

// AddClient adds a new client to the store.
func (s *ClientStore) AddClient(client Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[client.ID] = client
}

// GetClient retrieves a client from the store by its ID. It returns the client and a boolean indicating if the client was found.
func (s *ClientStore) GetClient(id string) (Client, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, exists := s.clients[id]
	return client, exists
}

// ValidateClient checks if the provided client ID and secret match a client in the store. It returns true if the client is valid, otherwise false.
func (s *ClientStore) ValidateClient(id, secret string) bool {
	client, exists := s.GetClient(id)
	if !exists {
		return false
	}
	return client.Secret == secret
}
