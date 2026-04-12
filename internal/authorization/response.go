package authorization

import "github.com/gin-gonic/gin"

// AuthorizationResponse represents the response sent by the authorization server to the client application after processing an authorization request.
type AuthorizationResponse struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

// NewAuthorizationResponse creates a new AuthorizationResponse with the given code and state.
func NewAuthorizationResponse(code, state string) AuthorizationResponse {
	return AuthorizationResponse{
		Code:  code,
		State: state,
	}
}

// IsValid checks if the authorization response has a valid code and state.
func (r AuthorizationResponse) IsValid() bool {
	return r.Code != "" && r.State != ""
}

// RedirectURI constructs the redirect URI with the authorization code and state as query parameters.
func (r AuthorizationResponse) RedirectURI(baseURL string) string {
	return baseURL + "?code=" + r.Code + "&state=" + r.State
}

// RedirectURIWithError constructs the redirect URI with an error message and state as query parameters.
func (r AuthorizationResponse) RedirectURIWithError(baseURL, errorMsg string) string {
	return baseURL + "?error=" + errorMsg + "&state=" + r.State
}

// RedirectURIWithErrorDescription constructs the redirect URI with an error message, error description, and state as query parameters.
func (r AuthorizationResponse) RedirectURIWithErrorDescription(baseURL, errorMsg, errorDescription string) string {
	return baseURL + "?error=" + errorMsg + "&error_description=" + errorDescription + "&state=" + r.State
}

// RedirectURIWithErrorAndHint constructs the redirect URI with an error message, error description, error hint, and state as query parameters.
func (r AuthorizationResponse) RedirectURIWithErrorAndHint(baseURL, errorMsg, errorDescription, errorHint string) string {
	return baseURL + "?error=" + errorMsg + "&error_description=" + errorDescription + "&error_hint=" + errorHint + "&state=" + r.State
}

// WriteAuthorizationResponse writes the authorization response to the client by redirecting to the appropriate URI based on the validity of the response.
func WriteAuthorizationResponse(c *gin.Context, response AuthorizationResponse, baseURL string) {
	if response.IsValid() {
		c.Redirect(302, response.RedirectURI(baseURL))
	} else {
		c.Redirect(302, response.RedirectURIWithError(baseURL, "invalid_request"))
	}
}
