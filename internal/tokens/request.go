package tokens

// TokenRequest represents the incoming token exchange request
type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required"`
	Code         string `form:"code" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required,url"`
	ClientID     string `form:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret" binding:"required"`
}

// IsValid checks if the token request is valid
func (r TokenRequest) IsValid() bool {
	return r.GrantType == "authorization_code" &&
		r.Code != "" &&
		r.RedirectURI != "" &&
		r.ClientID != "" &&
		r.ClientSecret != ""
}
