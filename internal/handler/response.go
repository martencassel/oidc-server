package handler

// TokenResponse represents the response returned after a successful token exchange
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// IsValid checks if the TokenResponse contains valid data
func (r TokenResponse) IsValid() bool {
	return r.AccessToken != "" && r.TokenType != "" && r.ExpiresIn > 0
}

// NewTokenResponse creates a new instance of TokenResponse with the provided parameters
func NewTokenResponse(accessToken, tokenType string, expiresIn int, refreshToken string) TokenResponse {
	return TokenResponse{
		AccessToken:  accessToken,
		TokenType:    tokenType,
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
	}
}
