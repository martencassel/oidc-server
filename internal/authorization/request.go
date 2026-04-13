package authorization

import (
	"time"

	"github.com/martencassel/oidc-server/internal/client"
)

// AuthorizationRequest represents an authorization request sent by a client application to the authorization server.
type AuthorizationRequest struct {
	AccessType   string `form:"access_type"`
	ClientID     string `form:"client_id" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required"`
	ResponseType string `form:"response_type" binding:"required"`
	Scope        string `form:"scope"`
	State        string `form:"state" binding:"required"`
}

// IsValid checks if the authorization request has all required fields and valid response type.
func (r AuthorizationRequest) IsValid() bool {
	return r.ResponseType == "code" &&
		r.ClientID != "" &&
		r.State != "" &&
		r.RedirectURI != ""
}

// NewAuthorizationRequest creates a new AuthorizationRequest with the given parameters.
func NewAuthorizationRequest(responseType, clientID, state, redirectURI string) AuthorizationRequest {
	return AuthorizationRequest{
		ResponseType: responseType,
		ClientID:     clientID,
		State:        state,
		RedirectURI:  redirectURI,
	}
}

// ValidateClient checks if the client ID in the authorization request exists in the client store.
func (r AuthorizationRequest) ValidateClient(clients *client.ClientStore) bool {
	_, exists := clients.GetClient(r.ClientID)
	return exists
}

// ValidateRedirectURI checks if the redirect URI in the authorization request matches the registered redirect URI for the client.
func (r AuthorizationRequest) ValidateRedirectURI(clients *client.ClientStore) bool {
	client, exists := clients.GetClient(r.ClientID)
	if !exists {
		return false
	}
	if r.RedirectURI != "" {
		return r.RedirectURI == client.ID // In a real implementation, this should check against registered redirect URIs
	}
	return true
}

// Validate checks if the authorization request is valid by verifying the request parameters, client existence, and redirect URI.
func (r AuthorizationRequest) Validate(clients *client.ClientStore) bool {
	return r.IsValid() && r.ValidateClient(clients) && r.ValidateRedirectURI(clients)
}

// ToAuthorizationCode converts the AuthorizationRequest to an AuthorizationCode with a generated code and current timestamp.
func (r AuthorizationRequest) ToAuthorizationCode() AuthorizationCode {
	return AuthorizationCode{
		Code:      GenerateAuthorizationCode(),
		State:     r.State,
		IssuedAt:  time.Now(),
		ExpiresIn: 5 * time.Minute,
	}
}

// ToAuthorizationResponse converts the AuthorizationRequest to an AuthorizationResponse using the provided code.
func (r AuthorizationRequest) ToAuthorizationResponse(code string) AuthorizationResponse {
	return AuthorizationResponse{
		Code:  code,
		State: r.State,
	}
}
