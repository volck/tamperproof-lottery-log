package server

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"lottery-tlog/tlog"
)

// Server represents the lottery transparency log server
type Server struct {
	log        *tlog.LotteryLog
	logger     *slog.Logger
	tlsConfig  *tls.Config
	addr       string
	heartbeats map[string]time.Time // witnessID -> last heartbeat timestamp
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	TLS      TLSConfig `mapstructure:"tls"`
}

type TLSConfig struct {
	CertFile           string `mapstructure:"cert_file"`
	KeyFile            string `mapstructure:"key_file"`
	CAFile             string `mapstructure:"ca_file"`
	RequireClientCert  bool   `mapstructure:"require_client_cert"`
}

// NewServer creates a new lottery server
func NewServer(dataDir string, logger *slog.Logger) (*Server, error) {
	ll, err := tlog.NewLotteryLog(dataDir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create lottery log: %w", err)
	}

	return &Server{
		log:        ll,
		logger:     logger,
		heartbeats: make(map[string]time.Time),
	}, nil
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

	// Setup TLS
	if err := s.SetupTLS(config.TLS); err != nil {
		return err
	}

	// Setup routes
	mux := http.NewServeMux()
	
	// Public endpoints (no client cert required)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/tree/info", s.handleTreeInfo)
	mux.HandleFunc("/api/draws", s.handleListDraws)
	mux.HandleFunc("/api/draws/", s.handleGetDraw)
	mux.HandleFunc("/api/draws/since/", s.handleDrawsSince)
	mux.HandleFunc("/api/status", s.handleStatus)
	
	// Witness endpoints (client cert required)
	mux.HandleFunc("/api/witness/observe", s.requireWitnessCert(s.handleWitnessObserve))
	mux.HandleFunc("/api/witness/observations", s.requireWitnessCert(s.handleWitnessObservations))
	mux.HandleFunc("/api/witness/cosignatures", s.handleGetCosignatures)
	mux.HandleFunc("/api/witness/heartbeat", s.handleWitnessHeartbeat)
	
	// Admin endpoints (client cert required with specific CN)
	mux.HandleFunc("/api/admin/draw", s.requireAdminCert(s.handleAddDraw))

	server := &http.Server{
		Addr:      s.addr,
		Handler:   mux,
		TLSConfig: s.tlsConfig,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	s.logger.Info("Starting lottery transparency log server", 
		"address", s.addr, 
		"mtls", config.TLS.RequireClientCert)

	if err := server.ListenAndServeTLS("", ""); err != nil {
		return fmt.Errorf("server failed: %w", err)
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
		hash, err := s.log.GetTreeHash()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		treeHash = fmt.Sprintf("%x", hash[:])
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
		"since_tree_size": sinceSize,
		"current_tree_size": currentSize,
		"new_draws_count": len(newDraws),
		"draws": newDraws,
	})
}

// Get status showing confirmed and unconfirmed draws
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	treeSize, err := s.log.GetTreeSize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	treeHash, err := s.log.GetTreeHash()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Find the highest tree size that has been witnessed
	// Check current size and previous sizes
	lastWitnessedSize := int64(0)
	witnessedTreeSizes := make(map[int64]int) // tree_size -> witness count
	type WitnessInfo struct {
		WitnessID        string    `json:"witness_id"`
		LastTreeSize     int64     `json:"last_tree_size"`
		LastSignatureAt  time.Time `json:"last_signature_at"`
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
		Online           bool      `json:"online"`
		LastHeartbeat    time.Time `json:"last_heartbeat,omitempty"`
		SecondsSinceHB   int       `json:"seconds_since_heartbeat,omitempty"`
	}

	witnessStatuses := make([]*WitnessStatus, 0, len(witnessDetails))
	for _, info := range witnessDetails {
		ws := &WitnessStatus{
			WitnessInfo: info,
		}
		if hbTime, ok := s.heartbeats[info.WitnessID]; ok {
			ws.LastHeartbeat = hbTime
			ws.SecondsSinceHB = int(time.Since(hbTime).Seconds())
			// Consider online if heartbeat within last 30 seconds
			ws.Online = time.Since(hbTime) < 30*time.Second
		}
		witnessStatuses = append(witnessStatuses, ws)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":                status,
		"tree_size":             treeSize,
		"tree_hash":             fmt.Sprintf("%x", treeHash),
		"last_witnessed_size":   lastWitnessedSize,
		"unconfirmed_count":     unconfirmedCount,
		"active_witnesses":      len(witnessDetails),
		"witnesses":             witnessStatuses,
		"witnessed_tree_sizes":  witnessedTreeSizes,
	})
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

	treeHash, err := s.log.GetTreeHash()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if witness is submitting a signature
	var requestBody struct {
		Signature string `json:"signature"`
	}
	
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			s.logger.Warn("Failed to decode request body", "error", err)
		} else {
			s.logger.Info("Decoded request body", "has_signature", requestBody.Signature != "")
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
		"witness_id":      witnessID,
		"tree_size":       treeSize,
		"tree_hash":       fmt.Sprintf("%x", treeHash[:]),
		"timestamp":       time.Now().Format(time.RFC3339),
		"witness_count":   len(cosignatures),
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
	s.heartbeats[witnessID] = time.Now()
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
	s.logger.Info("Draw added by admin", "draw_id", draw.DrawID, "new_tree_size", treeSize)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"draw_id":   draw.DrawID,
		"tree_size": treeSize,
	})
}
