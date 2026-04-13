package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/martencassel/oidc-server/internal/session"
	"github.com/martencassel/oidc-server/internal/users"
)

type LoginHandler struct {
	userStore    users.UserStore
	sessionStore *session.Store
}

func NewLoginHandler(userStore users.UserStore, sessionStore *session.Store) *LoginHandler {
	return &LoginHandler{
		userStore:    userStore,
		sessionStore: sessionStore,
	}
}

func (h *LoginHandler) RegisterRoutes(r *gin.Engine) {
	r.GET("/login", h.LoginGET)
	r.POST("/login", h.LoginPOST)
}

func (h *LoginHandler) LoginGET(c *gin.Context) {
	// The authorize endpoint will redirect here with ?return_to=/oauth2/authorize&client_id=...
	returnTo := c.Query("return_to")

	c.HTML(200, "login.html", gin.H{
		"return_to": returnTo,
	})
}

func (h *LoginHandler) LoginPOST(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	returnTo := c.PostForm("return_to")

	// Authenticate user
	user, ok := h.userStore.Authenticate(username, password)
	if !ok {
		c.HTML(401, "login.html", gin.H{
			"error":     "Invalid username or password",
			"return_to": returnTo,
		})
		return
	}

	// Create session
	sessionID := uuid.NewString()
	h.sessionStore.Set(sessionID, session.Session{
		Subject: user.Subject,
	})

	// Set cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "sid",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // set true in production
	})

	// Redirect back to authorize endpoint
	c.Redirect(302, returnTo)
}
