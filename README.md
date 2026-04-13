# oidc-server

Client → /oauth2/authorize
           ↓ (user not logged in)
         /login
           ↓ (POST credentials)
         authenticate user
           ↓
         create session
           ↓
         redirect back to /oauth2/authorize
           ↓
         issue authorization code (with sub)
           ↓
Client → /oauth2/token
           ↓
         GetClaims(sub, scopes, client)
           ↓
         issue ID token + access token
