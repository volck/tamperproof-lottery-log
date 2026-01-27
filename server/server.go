package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"lottery-tlog/tlog"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Server represents the lottery transparency log server
type Server struct {
	log           *tlog.LotteryLog
	logger        *slog.Logger
	tlsConfig     *tls.Config
	addr          string
	dataDir       string               // Data directory for witness operations
	heartbeats    map[string]time.Time // witnessID -> last heartbeat timestamp
	heartbeatsMux sync.RWMutex
	authMethod    string // "oidc" or "mtls"
	oidcProvider  *oidc.Provider
	oidcVerifier  *oidc.IDTokenVerifier
	oauth2Config  *oauth2.Config
	oidcConfig    OIDCConfig
	sessions      map[string]*Session // sessionID -> Session
	sessionsMutex sync.RWMutex
}

// Session represents an authenticated user session
type Session struct {
	Email        string
	IsAdmin      bool
	IsWitness    bool
	CreatedAt    time.Time
	ExpiresAt    time.Time
	LastAccessed time.Time
	RefreshToken string // OAuth2 refresh token for renewal
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Host       string     `mapstructure:"host"`
	Port       int        `mapstructure:"port"`
	TLS        TLSConfig  `mapstructure:"tls"`
	AuthMethod string     `mapstructure:"auth_method"`
	OIDC       OIDCConfig `mapstructure:"oidc"`
}

type TLSConfig struct {
	CertFile          string `mapstructure:"cert_file"`
	KeyFile           string `mapstructure:"key_file"`
	CAFile            string `mapstructure:"ca_file"`
	RequireClientCert bool   `mapstructure:"require_client_cert"`
}

type OIDCConfig struct {
	Enabled                   bool     `mapstructure:"enabled"`
	IssuerURL                 string   `mapstructure:"issuer_url"`
	ClientID                  string   `mapstructure:"client_id"`
	ClientSecret              string   `mapstructure:"client_secret"`
	RedirectURL               string   `mapstructure:"redirect_url"`
	CACertFile                string   `mapstructure:"ca_cert_file"`
	RequireClientCertForToken bool     `mapstructure:"require_client_cert_for_token"`
	AllowedDomains            []string `mapstructure:"allowed_domains"`
	AdminEmails               []string `mapstructure:"admin_emails"`
	WitnessEmails             []string `mapstructure:"witness_emails"`
}

// NewServer creates a new lottery server
func NewServer(dataDir string, logger *slog.Logger) (*Server, error) {
	ll, err := tlog.NewLotteryLog(dataDir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create lottery log: %w", err)
	}

	s := &Server{
		log:        ll,
		logger:     logger,
		dataDir:    dataDir,
		heartbeats: make(map[string]time.Time),
		sessions:   make(map[string]*Session),
		authMethod: "oidc", // Default to OIDC
	}

	// Start session cleanup goroutine
	go s.sessionCleanupLoop()

	return s, nil
}

// SetupOIDC configures OpenID Connect authentication
func (s *Server) SetupOIDC(config OIDCConfig) error {
	if !config.Enabled {
		s.logger.Info("OIDC authentication disabled")
		return nil
	}

	ctx := context.Background()

	// Create HTTP client with custom CA if provided
	var httpClient *http.Client
	if config.CACertFile != "" {
		caCert, err := os.ReadFile(config.CACertFile)
		if err != nil {
			return fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to parse CA certificate")
		}
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCertPool,
				},
			},
		}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
		s.logger.Info("Using custom CA certificate for OIDC", "ca_file", config.CACertFile)
	}

	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	s.oidcProvider = provider
	s.oidcVerifier = provider.Verifier(&oidc.Config{
		ClientID:          config.ClientID,
		SkipClientIDCheck: true, // Allow tokens from any client in the realm
	})
	s.oidcConfig = config

	s.oauth2Config = &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	s.logger.Info("OIDC authentication configured",
		"issuer", config.IssuerURL,
		"client_id", config.ClientID,
		"admin_count", len(config.AdminEmails),
		"witness_count", len(config.WitnessEmails))

	return nil
}

// SetupTLS configures mTLS for witness authentication
func (s *Server) SetupTLS(config TLSConfig) error {
	// Load server certificate
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load server certificate: %w", err)
	}

	// Configure mTLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// For development: accept any client certificate without CA verification
	// In production, you would set up a proper CA and verify against it
	if config.RequireClientCert {
		tlsConfig.ClientAuth = tls.RequireAnyClientCert
	} else {
		tlsConfig.ClientAuth = tls.RequestClientCert
	}

	s.tlsConfig = tlsConfig
	s.logger.Info("TLS configured", "require_client_cert", config.RequireClientCert, "mode", "dev")
	return nil
}

// Start starts the HTTPS server with mTLS
func (s *Server) Start(config ServerConfig) error {
	s.addr = fmt.Sprintf("%s:%d", config.Host, config.Port)
	s.authMethod = config.AuthMethod
	if s.authMethod == "" {
		s.authMethod = "oidc" // Default to OIDC
	}

	// Setup authentication
	if s.authMethod == "oidc" {
		if err := s.SetupOIDC(config.OIDC); err != nil {
			return fmt.Errorf("failed to setup OIDC: %w", err)
		}
	} else if s.authMethod == "mtls" {
		// Setup TLS for mTLS
		if err := s.SetupTLS(config.TLS); err != nil {
			return err
		}
	}

	// Setup routes
	mux := http.NewServeMux()

	// Public endpoints (no authentication required)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/tree/info", s.handleTreeInfo)
	mux.HandleFunc("/api/draws", s.handleListDraws)
	mux.HandleFunc("/api/draws/", s.handleGetDraw)
	mux.HandleFunc("/api/draws/since/", s.handleDrawsSince)
	mux.HandleFunc("/api/status", s.handleStatus)

	// OIDC authentication endpoints
	if s.authMethod == "oidc" {
		mux.HandleFunc("/auth/login", s.handleOIDCLogin)
		mux.HandleFunc("/auth/callback", s.handleOIDCCallback)
		mux.HandleFunc("/auth/logout", s.handleOIDCLogout)
		mux.HandleFunc("/auth/user", s.handleGetUser)
		mux.HandleFunc("/auth/refresh", s.handleRefreshSession)
	}

	// Witness endpoints (authentication required)
	mux.HandleFunc("/api/witness/observe", s.requireAuth("witness", s.handleWitnessObserve))
	mux.HandleFunc("/api/witness/observations", s.requireAuth("witness", s.handleWitnessObservations))
	mux.HandleFunc("/api/witness/cosignatures", s.handleGetCosignatures)
	mux.HandleFunc("/api/witness/heartbeat", s.handleWitnessHeartbeat)

	// Witness gossip endpoints (for cross-checking)
	mux.HandleFunc("/api/witness/gossip", s.handleWitnessGossip)
	mux.HandleFunc("/api/witness/", s.handleWitnessLatestState)

	// Admin endpoints (admin authentication required)
	mux.HandleFunc("/api/admin/draw", s.requireAuth("admin", s.handleAddDraw))

	var server *http.Server

	if s.authMethod == "mtls" && s.tlsConfig != nil {
		// Use mTLS
		server = &http.Server{
			Addr:         s.addr,
			Handler:      mux,
			TLSConfig:    s.tlsConfig,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		s.logger.Info("Starting lottery transparency log server",
			"address", s.addr,
			"auth_method", "mtls")
		if err := server.ListenAndServeTLS("", ""); err != nil {
			return fmt.Errorf("server failed: %w", err)
		}
	} else {
		// Use HTTPS with OIDC
		server = &http.Server{
			Addr:         s.addr,
			Handler:      mux,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		s.logger.Info("Starting lottery transparency log server",
			"address", s.addr,
			"auth_method", s.authMethod)

		// Check if TLS certificates exist for HTTPS
		if config.TLS.CertFile != "" && config.TLS.KeyFile != "" {
			if err := server.ListenAndServeTLS(config.TLS.CertFile, config.TLS.KeyFile); err != nil {
				return fmt.Errorf("server failed: %w", err)
			}
		} else {
			s.logger.Warn("Starting HTTP server (no TLS certificates provided)")
			if err := server.ListenAndServe(); err != nil {
				return fmt.Errorf("server failed: %w", err)
			}
		}
	}

	return nil
}

// Middleware to require witness certificate
func (s *Server) requireWitnessCert(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "Client certificate required", http.StatusUnauthorized)
			return
		}

		clientCert := r.TLS.PeerCertificates[0]
		witnessID := clientCert.Subject.CommonName

		s.logger.Info("Witness authenticated", "witness_id", witnessID, "subject", clientCert.Subject.String())

		// Add witness ID to context for handlers
		r.Header.Set("X-Witness-ID", witnessID)

		next(w, r)
	}
}

// Middleware to require admin certificate
func (s *Server) requireAdminCert(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "Client certificate required", http.StatusUnauthorized)
			return
		}

		clientCert := r.TLS.PeerCertificates[0]
		commonName := clientCert.Subject.CommonName

		// Check if certificate is marked as admin (CN contains "admin" or has specific OU)
		isAdmin := false
		for _, ou := range clientCert.Subject.OrganizationalUnit {
			if ou == "admin" || ou == "operator" {
				isAdmin = true
				break
			}
		}

		if !isAdmin {
			s.logger.Warn("Unauthorized admin access attempt", "subject", clientCert.Subject.String())
			http.Error(w, "Admin certificate required", http.StatusForbidden)
			return
		}

		s.logger.Info("Admin authenticated", "common_name", commonName, "subject", clientCert.Subject.String())

		next(w, r)
	}
}

// Unified authentication middleware that supports both OIDC and mTLS
func (s *Server) requireAuth(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authMethod == "mtls" {
			// Use mTLS authentication
			if role == "admin" {
				s.requireAdminCert(next)(w, r)
			} else {
				s.requireWitnessCert(next)(w, r)
			}
			return
		}

		// Use OIDC authentication - check Bearer token first, then session cookie
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			token := authHeader[7:]

			// Verify JWT token
			idToken, err := s.oidcVerifier.Verify(r.Context(), token)
			if err != nil {
				s.logger.Warn("Invalid JWT token", "error", err)
				http.Error(w, "Invalid authentication token", http.StatusUnauthorized)
				return
			}

			// Extract claims
			var claims struct {
				Email         string `json:"email"`
				EmailVerified bool   `json:"email_verified"`
			}
			if err := idToken.Claims(&claims); err != nil {
				s.logger.Warn("Failed to parse token claims", "error", err)
				http.Error(w, "Invalid token claims", http.StatusUnauthorized)
				return
			}

			// Check role-based access
			isAdmin := false
			isWitness := false

			for _, adminEmail := range s.oidcConfig.AdminEmails {
				if claims.Email == adminEmail {
					isAdmin = true
					break
				}
			}

			for _, witnessEmail := range s.oidcConfig.WitnessEmails {
				if claims.Email == witnessEmail {
					isWitness = true
					break
				}
			}

			if role == "admin" && !isAdmin {
				s.logger.Warn("Unauthorized admin access attempt via token", "email", claims.Email)
				http.Error(w, "Admin access required", http.StatusForbidden)
				return
			}

			if role == "witness" && !isWitness && !isAdmin {
				s.logger.Warn("Unauthorized witness access attempt via token", "email", claims.Email)
				http.Error(w, "Witness access required", http.StatusForbidden)
				return
			}

			// Add user info to headers for handlers
			r.Header.Set("X-User-Email", claims.Email)
			if isAdmin {
				r.Header.Set("X-User-Role", "admin")
			} else if isWitness {
				r.Header.Set("X-User-Role", "witness")
			}

			next(w, r)
			return
		}

		// Fall back to session cookie authentication
		session := s.getSessionFromRequest(r)
		if session == nil {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		// Check if session is expired
		if time.Now().After(session.ExpiresAt) {
			s.deleteSession(r)
			http.Error(w, "Session expired", http.StatusUnauthorized)
			return
		}

		// Update last accessed time for idle timeout tracking
		s.sessionsMutex.Lock()
		session.LastAccessed = time.Now()
		s.sessionsMutex.Unlock()

		// Check role-based access
		if role == "admin" && !session.IsAdmin {
			s.logger.Warn("Unauthorized admin access attempt", "email", session.Email)
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}

		if role == "witness" && !session.IsWitness && !session.IsAdmin {
			s.logger.Warn("Unauthorized witness access attempt", "email", session.Email)
			http.Error(w, "Witness access required", http.StatusForbidden)
			return
		}

		// Add user info to headers for handlers
		r.Header.Set("X-User-Email", session.Email)
		if session.IsAdmin {
			r.Header.Set("X-User-Role", "admin")
		} else if session.IsWitness {
			r.Header.Set("X-User-Role", "witness")
		}

		next(w, r)
	}
}

// Session management helpers
func (s *Server) getSessionFromRequest(r *http.Request) *Session {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil
	}

	s.sessionsMutex.RLock()
	defer s.sessionsMutex.RUnlock()
	return s.sessions[cookie.Value]
}

func (s *Server) createSession(email string, isAdmin, isWitness bool, refreshToken string) string {
	sessionID := s.generateSessionID()
	now := time.Now()
	session := &Session{
		Email:        email,
		IsAdmin:      isAdmin,
		IsWitness:    isWitness,
		CreatedAt:    now,
		ExpiresAt:    now.Add(24 * time.Hour),
		LastAccessed: now,
		RefreshToken: refreshToken,
	}

	s.sessionsMutex.Lock()
	s.sessions[sessionID] = session
	s.sessionsMutex.Unlock()

	s.logger.Info("Session created",
		"email", email,
		"session_id", sessionID[:8]+"...",
		"expires_at", session.ExpiresAt.Format(time.RFC3339))

	return sessionID
}

func (s *Server) deleteSession(r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return
	}

	s.sessionsMutex.Lock()
	delete(s.sessions, cookie.Value)
	s.sessionsMutex.Unlock()

	s.logger.Info("Session deleted", "session_id", cookie.Value[:8]+"...")
}

// sessionCleanupLoop periodically removes expired sessions
func (s *Server) sessionCleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.cleanupExpiredSessions()
	}
}

// cleanupExpiredSessions removes expired and idle sessions
func (s *Server) cleanupExpiredSessions() {
	now := time.Now()
	idleTimeout := 30 * time.Minute

	s.sessionsMutex.Lock()
	defer s.sessionsMutex.Unlock()

	initialCount := len(s.sessions)
	removed := 0

	for sessionID, session := range s.sessions {
		// Remove if expired
		if now.After(session.ExpiresAt) {
			delete(s.sessions, sessionID)
			removed++
			s.logger.Debug("Removed expired session",
				"session_id", sessionID[:8]+"...",
				"email", session.Email,
				"expired_at", session.ExpiresAt.Format(time.RFC3339))
			continue
		}

		// Remove if idle too long
		if now.Sub(session.LastAccessed) > idleTimeout {
			delete(s.sessions, sessionID)
			removed++
			s.logger.Debug("Removed idle session",
				"session_id", sessionID[:8]+"...",
				"email", session.Email,
				"last_accessed", session.LastAccessed.Format(time.RFC3339))
		}
	}

	if removed > 0 {
		s.logger.Info("Session cleanup completed",
			"initial_count", initialCount,
			"removed", removed,
			"remaining", len(s.sessions))
	}
}

func (s *Server) generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// OIDC Authentication Handlers
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	state := s.generateSessionID()

	// Store state in a temporary cookie for validation
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	url := s.oauth2Config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		http.Error(w, "State cookie not found", http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	oauth2Token, err := s.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		s.logger.Error("Failed to exchange token", "error", err)
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Extract ID Token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token in token response", http.StatusInternalServerError)
		return
	}

	// Verify ID Token
	idToken, err := s.oidcVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		s.logger.Error("Failed to verify ID token", "error", err)
		http.Error(w, "Failed to verify token", http.StatusInternalServerError)
		return
	}

	// Extract claims
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
		return
	}

	if !claims.EmailVerified {
		http.Error(w, "Email not verified", http.StatusForbidden)
		return
	}

	// Check domain restrictions
	if len(s.oidcConfig.AllowedDomains) > 0 {
		allowed := false
		for _, domain := range s.oidcConfig.AllowedDomains {
			if strings.HasSuffix(claims.Email, "@"+domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			s.logger.Warn("Domain not allowed", "email", claims.Email)
			http.Error(w, "Domain not allowed", http.StatusForbidden)
			return
		}
	}

	// Determine roles
	isAdmin := false
	for _, adminEmail := range s.oidcConfig.AdminEmails {
		if claims.Email == adminEmail {
			isAdmin = true
			break
		}
	}

	isWitness := isAdmin // Admins are also witnesses
	if !isWitness {
		for _, witnessEmail := range s.oidcConfig.WitnessEmails {
			if claims.Email == witnessEmail {
				isWitness = true
				break
			}
		}
	}

	// Create session with refresh token
	refreshToken := ""
	if oauth2Token.RefreshToken != "" {
		refreshToken = oauth2Token.RefreshToken
	}
	sessionID := s.createSession(claims.Email, isAdmin, isWitness, refreshToken)

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		MaxAge:   86400, // 24 hours
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "oauth_state",
		Value:  "",
		MaxAge: -1,
	})

	s.logger.Info("User authenticated",
		"email", claims.Email,
		"is_admin", isAdmin,
		"is_witness", isWitness)

	// Redirect to application
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (s *Server) handleOIDCLogout(w http.ResponseWriter, r *http.Request) {
	s.deleteSession(r)

	http.SetCookie(w, &http.Cookie{
		Name:   "session_id",
		Value:  "",
		MaxAge: -1,
		Path:   "/",
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "logged out"})
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	session := s.getSessionFromRequest(r)
	if session == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"email":         session.Email,
		"is_admin":      session.IsAdmin,
		"is_witness":    session.IsWitness,
		"expires_at":    session.ExpiresAt,
		"last_accessed": session.LastAccessed,
		"created_at":    session.CreatedAt,
	})
}

func (s *Server) handleRefreshSession(w http.ResponseWriter, r *http.Request) {
	session := s.getSessionFromRequest(r)
	if session == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	// If session has a refresh token, use it to get a new access token
	if session.RefreshToken != "" && s.oauth2Config != nil {
		// Create token source with refresh token
		token := &oauth2.Token{
			RefreshToken: session.RefreshToken,
		}

		tokenSource := s.oauth2Config.TokenSource(r.Context(), token)
		newToken, err := tokenSource.Token()

		if err != nil {
			s.logger.Warn("Failed to refresh OAuth2 token", "error", err, "email", session.Email)
			http.Error(w, "Failed to refresh token", http.StatusUnauthorized)
			return
		}

		// Update session with new refresh token if provided
		s.sessionsMutex.Lock()
		if newToken.RefreshToken != "" {
			session.RefreshToken = newToken.RefreshToken
		}
		session.ExpiresAt = time.Now().Add(24 * time.Hour)
		session.LastAccessed = time.Now()
		s.sessionsMutex.Unlock()

		s.logger.Info("Session refreshed",
			"email", session.Email,
			"new_expires_at", session.ExpiresAt.Format(time.RFC3339))
	} else {
		// No refresh token - just extend the session
		s.sessionsMutex.Lock()
		session.ExpiresAt = time.Now().Add(24 * time.Hour)
		session.LastAccessed = time.Now()
		s.sessionsMutex.Unlock()

		s.logger.Info("Session extended",
			"email", session.Email,
			"new_expires_at", session.ExpiresAt.Format(time.RFC3339))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "refreshed",
		"expires_at": session.ExpiresAt,
	})
}

// Health check endpoint
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

// Get tree information
func (s *Server) handleTreeInfo(w http.ResponseWriter, r *http.Request) {
	treeSize, err := s.log.GetTreeSize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var treeHash string
	if treeSize > 0 {
		hash, err := s.log.GetTreeHash(treeSize)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		treeHash = hash
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tree_size": treeSize,
		"tree_hash": treeHash,
	})
}

// List all draws
func (s *Server) handleListDraws(w http.ResponseWriter, r *http.Request) {
	draws, err := s.log.ListAllDraws()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(draws)
}

// Get specific draw
func (s *Server) handleGetDraw(w http.ResponseWriter, r *http.Request) {
	// Extract draw index from path
	var index int64
	if _, err := fmt.Sscanf(r.URL.Path, "/api/draws/%d", &index); err != nil {
		http.Error(w, "Invalid draw index", http.StatusBadRequest)
		return
	}

	draw, err := s.log.GetDraw(index)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(draw)
}

// Get draws since a specific tree size
func (s *Server) handleDrawsSince(w http.ResponseWriter, r *http.Request) {
	// Extract tree size from path: /api/draws/since/777
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/draws/since/"), "/")
	if len(pathParts) == 0 || pathParts[0] == "" {
		http.Error(w, "Missing tree size", http.StatusBadRequest)
		return
	}

	sinceSize, err := strconv.ParseInt(pathParts[0], 10, 64)
	if err != nil {
		http.Error(w, "Invalid tree size", http.StatusBadRequest)
		return
	}

	currentSize, err := s.log.GetTreeSize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if sinceSize < 0 || sinceSize >= currentSize {
		http.Error(w, "Invalid tree size range", http.StatusBadRequest)
		return
	}

	// Get all draws from sinceSize+1 to currentSize
	var newDraws []tlog.LotteryDraw
	for i := sinceSize; i < currentSize; i++ {
		draw, err := s.log.GetDraw(i)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get draw %d: %v", i, err), http.StatusInternalServerError)
			return
		}
		newDraws = append(newDraws, *draw)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"since_tree_size":   sinceSize,
		"current_tree_size": currentSize,
		"new_draws_count":   len(newDraws),
		"draws":             newDraws,
	})
}

// Get status showing confirmed and unconfirmed draws
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	treeSize, err := s.log.GetTreeSize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	treeHash, err := s.log.GetTreeHash(treeSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Find the highest tree size that has been witnessed
	// Check current size and previous sizes
	lastWitnessedSize := int64(0)
	witnessedTreeSizes := make(map[int64]int) // tree_size -> witness count
	type WitnessInfo struct {
		WitnessID       string    `json:"witness_id"`
		LastTreeSize    int64     `json:"last_tree_size"`
		LastSignatureAt time.Time `json:"last_signature_at"`
	}
	witnessDetails := make(map[string]*WitnessInfo) // witness_id -> info

	// Check current tree size and go backwards
	for checkSize := treeSize; checkSize > 0 && checkSize > treeSize-10; checkSize-- {
		cosigs, err := s.log.GetWitnessCosignatures(checkSize)
		if err == nil && len(cosigs) > 0 {
			for _, cosig := range cosigs {
				witnessedTreeSizes[cosig.TreeSize]++
				if cosig.TreeSize > lastWitnessedSize {
					lastWitnessedSize = cosig.TreeSize
				}
				// Track latest signature per witness
				if existing, ok := witnessDetails[cosig.WitnessID]; !ok || cosig.TreeSize > existing.LastTreeSize {
					witnessDetails[cosig.WitnessID] = &WitnessInfo{
						WitnessID:       cosig.WitnessID,
						LastTreeSize:    cosig.TreeSize,
						LastSignatureAt: cosig.Timestamp,
					}
				}
			}
		}
	}

	// Calculate unconfirmed draws
	unconfirmedCount := int64(0)
	if treeSize > lastWitnessedSize {
		unconfirmedCount = treeSize - lastWitnessedSize
	}

	// Determine status
	status := "healthy"
	if unconfirmedCount > 0 {
		status = "pending_witnesses"
	}
	if treeSize == 0 {
		status = "empty"
	}

	// Convert witness details to slice for JSON response and add heartbeat info
	type WitnessStatus struct {
		*WitnessInfo
		Online         bool      `json:"online"`
		LastHeartbeat  time.Time `json:"last_heartbeat,omitempty"`
		SecondsSinceHB int       `json:"seconds_since_heartbeat,omitempty"`
	}

	witnessStatuses := make([]*WitnessStatus, 0, len(witnessDetails))
	for _, info := range witnessDetails {
		ws := &WitnessStatus{
			WitnessInfo: info,
		}
		s.heartbeatsMux.RLock()
		if hbTime, ok := s.heartbeats[info.WitnessID]; ok {
			ws.LastHeartbeat = hbTime
			ws.SecondsSinceHB = int(time.Since(hbTime).Seconds())
			// Consider online if heartbeat within last 30 seconds
			ws.Online = time.Since(hbTime) < 30*time.Second
		}
		s.heartbeatsMux.RUnlock()
		witnessStatuses = append(witnessStatuses, ws)
	}

	// Check quorum if configured (example: require 2/3 of 3 witnesses)
	var quorumStatus map[string]interface{}
	if len(witnessDetails) > 0 {
		// Example quorum config - could be loaded from config file
		knownWitnesses := make([]string, 0, len(witnessDetails))
		for witnessID := range witnessDetails {
			knownWitnesses = append(knownWitnesses, witnessID)
		}

		quorumConfig := tlog.QuorumConfig{
			MinWitnesses:    2,
			QuorumThreshold: 0.67,
			KnownWitnesses:  knownWitnesses,
		}

		cosignatures, _ := s.log.GetWitnessCosignatures(treeSize)
		quorumResult, _ := tlog.CheckQuorum(cosignatures, quorumConfig, treeSize, treeHash)

		if quorumResult != nil {
			quorumStatus = map[string]interface{}{
				"quorum_achieved":     quorumResult.QuorumAchieved,
				"required_signatures": quorumResult.RequiredSignatures,
				"received_signatures": quorumResult.ReceivedSignatures,
				"signing_witnesses":   quorumResult.SigningWitnesses,
				"missing_witnesses":   quorumResult.MissingWitnesses,
				"threshold":           quorumConfig.QuorumThreshold,
				"details":             quorumResult.Details,
			}
		}
	}

	response := map[string]interface{}{
		"status":               status,
		"tree_size":            treeSize,
		"tree_hash":            fmt.Sprintf("%x", treeHash),
		"last_witnessed_size":  lastWitnessedSize,
		"unconfirmed_count":    unconfirmedCount,
		"active_witnesses":     len(witnessDetails),
		"witnesses":            witnessStatuses,
		"witnessed_tree_sizes": witnessedTreeSizes,
	}

	if quorumStatus != nil {
		response["quorum"] = quorumStatus
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Witness observes tree state (mTLS authenticated)
func (s *Server) handleWitnessObserve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	witnessID := r.Header.Get("X-Witness-ID")

	treeSize, err := s.log.GetTreeSize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if treeSize == 0 {
		http.Error(w, "No draws to observe", http.StatusBadRequest)
		return
	}

	treeHash, err := s.log.GetTreeHash(treeSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if witness is submitting a signature
	var requestBody struct {
		Signature string `json:"signature"`
	}

	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil && err != io.EOF {
			s.logger.Warn("Failed to decode request body", "error", err)
		}
	}

	// If witness provided a signature, store it as a cosignature
	if requestBody.Signature != "" {
		s.logger.Info("Storing witness cosignature", "witness_id", witnessID, "tree_size", treeSize)
		cosig := tlog.WitnessCosignature{
			WitnessID: witnessID,
			TreeSize:  treeSize,
			TreeHash:  fmt.Sprintf("%x", treeHash[:]),
			Timestamp: time.Now(),
			Signature: requestBody.Signature,
		}

		if err := s.log.AddWitnessCosignature(cosig); err != nil {
			// Don't fail if witness already signed - just log it
			s.logger.Warn("Failed to store cosignature", "witness_id", witnessID, "error", err)
		} else {
			s.logger.Info("Successfully stored cosignature", "witness_id", witnessID)
		}
	}

	// Get all cosignatures for this tree state
	cosignatures, _ := s.log.GetWitnessCosignatures(treeSize)

	observation := map[string]interface{}{
		"witness_id":    witnessID,
		"tree_size":     treeSize,
		"tree_hash":     fmt.Sprintf("%x", treeHash[:]),
		"timestamp":     time.Now().Format(time.RFC3339),
		"witness_count": len(cosignatures),
	}

	s.logger.Info("Tree state observed", "witness_id", witnessID, "tree_size", treeSize, "cosignatures", len(cosignatures))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(observation)
}

// Get witness observations (mTLS authenticated)
func (s *Server) handleWitnessObservations(w http.ResponseWriter, r *http.Request) {
	witnessID := r.Header.Get("X-Witness-ID")

	// TODO: Load and return witness's observation history
	// For now, return placeholder

	observations := []map[string]interface{}{
		{
			"witness_id": witnessID,
			"message":    "Observation history not yet implemented",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(observations)
}

// Get all witness cosignatures for current or specified tree state
func (s *Server) handleGetCosignatures(w http.ResponseWriter, r *http.Request) {
	// Parse tree_size query parameter if provided
	treeSize := int64(-1)
	if ts := r.URL.Query().Get("tree_size"); ts != "" {
		fmt.Sscanf(ts, "%d", &treeSize)
	}

	// If no tree_size specified, get current tree size
	if treeSize == -1 {
		var err error
		treeSize, err = s.log.GetTreeSize()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	cosignatures, err := s.log.GetWitnessCosignatures(treeSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tree_size":     treeSize,
		"witness_count": len(cosignatures),
		"cosignatures":  cosignatures,
	})
}

// Handle witness heartbeat
func (s *Server) handleWitnessHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	witnessID := r.Header.Get("X-Witness-ID")
	if witnessID == "" {
		http.Error(w, "Missing witness ID", http.StatusBadRequest)
		return
	}

	// Update heartbeat timestamp
	s.heartbeatsMux.Lock()
	s.heartbeats[witnessID] = time.Now()
	s.heartbeatsMux.Unlock()
	s.logger.Debug("Heartbeat received", "witness_id", witnessID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now(),
	})
}

// Add a new draw (admin only)
func (s *Server) handleAddDraw(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var draw tlog.LotteryDraw
	if err := json.NewDecoder(r.Body).Decode(&draw); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Set timestamp if not provided
	if draw.Timestamp.IsZero() {
		draw.Timestamp = time.Now()
	}

	if err := s.log.AddDraw(draw); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	treeSize, _ := s.log.GetTreeSize()
	s.logger.Info("Draw added by admin", "seqno", draw.SeqNo, "code", draw.Message.Code, "new_tree_size", treeSize)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"seqno":     draw.SeqNo,
		"code":      draw.Message.Code,
		"tree_size": treeSize,
	})
}

// handleWitnessGossip receives witnessed states from other witnesses for cross-checking
func (s *Server) handleWitnessGossip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var receivedState tlog.WitnessedState
	if err := json.NewDecoder(r.Body).Decode(&receivedState); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get current tree state
	treeSize, err := s.log.GetTreeSize()
	if err != nil {
		http.Error(w, "Failed to get tree size", http.StatusInternalServerError)
		return
	}

	treeHash, err := s.log.GetTreeHash(treeSize)
	if err != nil {
		http.Error(w, "Failed to get tree hash", http.StatusInternalServerError)
		return
	}

	// Compare with received state
	consistent := true
	details := ""

	if receivedState.TreeSize == treeSize {
		if receivedState.TreeHash != treeHash {
			consistent = false
			details = fmt.Sprintf("FORK DETECTED! Same tree size (%d) but different hashes: local=%s remote=%s",
				treeSize, treeHash[:16], receivedState.TreeHash[:16])
			s.logger.Error("Fork detected in witness gossip",
				"remote_witness", receivedState.WitnessID,
				"tree_size", treeSize,
				"local_hash", treeHash,
				"remote_hash", receivedState.TreeHash)
		} else {
			details = "Tree size and hash match exactly"
		}
	} else if receivedState.TreeSize > treeSize {
		details = fmt.Sprintf("Remote witness is ahead (size %d vs %d)", receivedState.TreeSize, treeSize)
	} else {
		details = fmt.Sprintf("Local is ahead (size %d vs %d)", treeSize, receivedState.TreeSize)
	}

	s.logger.Info("Received witness gossip",
		"remote_witness", receivedState.WitnessID,
		"remote_tree_size", receivedState.TreeSize,
		"local_tree_size", treeSize,
		"consistent", consistent,
		"details", details)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":         true,
		"consistent":      consistent,
		"details":         details,
		"local_tree_size": treeSize,
		"local_tree_hash": treeHash,
	})
}

// handleWitnessLatestState returns a witness's latest observed state
func (s *Server) handleWitnessLatestState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract witness ID from path: /api/witness/{witnessID}/latest
	path := r.URL.Path
	if len(path) < len("/api/witness/") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Parse path to extract witness ID
	pathParts := strings.Split(strings.TrimPrefix(path, "/api/witness/"), "/")
	if len(pathParts) < 2 || pathParts[1] != "latest" {
		http.Error(w, "Invalid path format. Use /api/witness/{witnessID}/latest", http.StatusBadRequest)
		return
	}

	witnessID := pathParts[0]

	// Load witness data
	wm, err := tlog.NewWitnessManager(s.dataDir, witnessID)
	if err != nil {
		http.Error(w, "Witness not found", http.StatusNotFound)
		return
	}

	states, err := wm.ListWitnessedStates()
	if err != nil {
		http.Error(w, "Failed to get witnessed states", http.StatusInternalServerError)
		return
	}

	if len(states) == 0 {
		http.Error(w, "No witnessed states found for this witness", http.StatusNotFound)
		return
	}

	latestState := states[len(states)-1]

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(latestState)
}
