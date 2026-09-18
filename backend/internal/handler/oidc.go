package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/inboxes/backend/internal/middleware"
	"github.com/inboxes/backend/internal/service"
	"github.com/inboxes/backend/internal/store"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

// OIDCHandler signs users in via an external OIDC identity provider instead
// of a password. It is only mounted when OIDC_ISSUER_URL is configured
// (see config.Load), at which point it is the only way to sign in — the app
// trusts the IdP to gate who reaches it (e.g. Cloudflare Access in front of
// the tunnel) and auto-provisions any identity the IdP vouches for.
type OIDCHandler struct {
	Store    store.Store
	RDB      *redis.Client
	Secret   string
	AppURL   string
	Provider *oidc.Provider
	OAuth2   oauth2.Config
	Verifier *oidc.IDTokenVerifier
}

type OIDCConfig struct {
	Store        store.Store
	RDB          *redis.Client
	Secret       string
	AppURL       string
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// NewOIDCHandler runs OIDC discovery against the issuer. Discovery is a
// network call, so this can fail if the IdP is briefly unreachable at boot —
// callers should treat that as fatal (same as the rest of config validation)
// and let the container's restart policy retry.
func NewOIDCHandler(ctx context.Context, cfg OIDCConfig) (*OIDCHandler, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery against %s: %w", cfg.IssuerURL, err)
	}

	return &OIDCHandler{
		Store:    cfg.Store,
		RDB:      cfg.RDB,
		Secret:   cfg.Secret,
		AppURL:   cfg.AppURL,
		Provider: provider,
		OAuth2: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		},
		Verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

const oidcCookieMaxAge = 10 * 60 // 10 minutes — just long enough for the IdP redirect round trip

// setOIDCCookie sets a short-lived cookie scoped to the OIDC flow itself, not
// the whole app, so it never rides along on ordinary API requests.
func (h *OIDCHandler) setOIDCCookie(w http.ResponseWriter, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/api/auth/oidc",
		MaxAge:   oidcCookieMaxAge,
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.AppURL, "https"),
		SameSite: http.SameSiteLaxMode, // Lax: this cookie must survive the IdP's top-level redirect back to us
	}
	if d := middleware.CookieDomain(h.AppURL); d != "" {
		c.Domain = d
	}
	http.SetCookie(w, c)
}

func (h *OIDCHandler) clearOIDCCookie(w http.ResponseWriter, name string) {
	c := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/api/auth/oidc",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.AppURL, "https"),
		SameSite: http.SameSiteLaxMode,
	}
	if d := middleware.CookieDomain(h.AppURL); d != "" {
		c.Domain = d
	}
	http.SetCookie(w, c)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// sanitizeNextPath allows only a same-origin relative path as a post-login
// redirect target, mirroring the frontend's own check for the same param —
// otherwise an open redirect could send a freshly authenticated session to
// an attacker's origin.
func sanitizeNextPath(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") {
		return ""
	}
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return ""
	}
	return raw
}

// Login starts the OIDC flow: stash CSRF state + a replay nonce in
// short-lived cookies, then redirect to the identity provider.
func (h *OIDCHandler) Login(w http.ResponseWriter, r *http.Request) {
	state, err := randomHex(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start sign-in")
		return
	}
	nonce, err := randomHex(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start sign-in")
		return
	}

	h.setOIDCCookie(w, "oidc_state", state)
	h.setOIDCCookie(w, "oidc_nonce", nonce)
	if next := sanitizeNextPath(r.URL.Query().Get("next")); next != "" {
		h.setOIDCCookie(w, "oidc_next", next)
	}

	http.Redirect(w, r, h.OAuth2.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

// Callback completes the OIDC flow: verifies state, exchanges the code,
// verifies the ID token (signature, issuer, audience, nonce), then
// provisions/looks up the user and issues the same session cookie password
// login would.
func (h *OIDCHandler) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stateCookie, stateErr := r.Cookie("oidc_state")
	nonceCookie, nonceErr := r.Cookie("oidc_nonce")
	var nextPath string
	if nextCookie, err := r.Cookie("oidc_next"); err == nil {
		nextPath = sanitizeNextPath(nextCookie.Value)
	}
	h.clearOIDCCookie(w, "oidc_state")
	h.clearOIDCCookie(w, "oidc_nonce")
	h.clearOIDCCookie(w, "oidc_next")

	if stateErr != nil || nonceErr != nil {
		writeError(w, http.StatusBadRequest, "sign-in session expired, please try again")
		return
	}
	if q := r.URL.Query().Get("state"); q == "" || q != stateCookie.Value {
		slog.Warn("oidc: state mismatch")
		writeError(w, http.StatusBadRequest, "invalid sign-in state")
		return
	}
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		slog.Warn("oidc: idp returned error", "error", errParam, "description", r.URL.Query().Get("error_description"))
		writeError(w, http.StatusBadRequest, "sign-in was not completed")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "missing authorization code")
		return
	}

	oauth2Token, err := h.OAuth2.Exchange(ctx, code)
	if err != nil {
		slog.Warn("oidc: code exchange failed", "error", err)
		writeError(w, http.StatusBadGateway, "sign-in failed")
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		slog.Warn("oidc: token response had no id_token")
		writeError(w, http.StatusBadGateway, "sign-in failed")
		return
	}

	idToken, err := h.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		slog.Warn("oidc: id_token verification failed", "error", err)
		writeError(w, http.StatusBadGateway, "sign-in failed")
		return
	}
	if idToken.Nonce != nonceCookie.Value {
		slog.Warn("oidc: nonce mismatch")
		writeError(w, http.StatusBadRequest, "invalid sign-in state")
		return
	}

	var claims struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil || claims.Email == "" {
		slog.Warn("oidc: id_token missing email claim", "error", err)
		writeError(w, http.StatusBadGateway, "identity provider did not return an email address")
		return
	}

	email := normalizeEmail(claims.Email)
	if err := validateEmail(email); err != nil {
		writeError(w, http.StatusBadGateway, "identity provider returned an invalid email address")
		return
	}
	name := strings.TrimSpace(claims.Name)
	if name == "" {
		name = strings.Split(email, "@")[0]
	}

	var userID, orgID, role string
	txErr := h.Store.WithTx(ctx, func(tx store.Store) error {
		var txErr error
		userID, orgID, role, txErr = tx.GetOrCreateOIDCUser(ctx, email, name)
		return txErr
	})
	if txErr != nil {
		slog.Error("oidc: provisioning failed", "error", txErr)
		writeError(w, http.StatusInternalServerError, "failed to sign in")
		return
	}

	token, jti, err := middleware.GenerateToken(h.Secret, userID, orgID, role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign in")
		return
	}
	middleware.SetTokenCookie(w, token, h.AppURL)
	service.NewTokenBlacklist(h.RDB).RegisterSession(ctx, userID, jti)

	slog.Info("auth: oidc login", "email", email)

	dest := h.AppURL + "/d"
	if nextPath != "" {
		dest = h.AppURL + nextPath
	}
	http.Redirect(w, r, dest, http.StatusFound)
}
