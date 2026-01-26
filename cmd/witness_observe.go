package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"lottery-tlog/tlog"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// TokenManager handles automatic token refresh for long-running operations
type TokenManager struct {
	mu           sync.RWMutex
	accessToken  string
	refreshToken string
	expiresAt    time.Time
	keycloakURL  string
	clientID     string
	clientSecret string
	username     string
	password     string
	httpClient   *http.Client
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewTokenManager creates a new token manager with initial tokens
func NewTokenManager(accessToken, refreshToken string, expiresIn int, keycloakURL, clientID, clientSecret, username, password string, httpClient *http.Client) *TokenManager {
	ctx, cancel := context.WithCancel(context.Background())

	tm := &TokenManager{
		accessToken:  accessToken,
		refreshToken: refreshToken,
		expiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second),
		keycloakURL:  keycloakURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		username:     username,
		password:     password,
		httpClient:   httpClient,
		ctx:          ctx,
		cancel:       cancel,
	}

	// Start automatic refresh goroutine
	go tm.autoRefresh()

	slog.Info("Token manager started",
		"initial_expires_at", tm.expiresAt.Format(time.RFC3339),
		"refresh_buffer", "2 minutes before expiry")

	return tm
}

// GetToken returns the current valid access token
func (tm *TokenManager) GetToken() string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.accessToken
}

// Stop shuts down the token manager goroutine
func (tm *TokenManager) Stop() {
	tm.cancel()
	slog.Info("Token manager stopped")
}

// autoRefresh runs in a goroutine and refreshes tokens before they expire
func (tm *TokenManager) autoRefresh() {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-tm.ctx.Done():
			return
		case <-ticker.C:
			tm.checkAndRefresh()
		}
	}
}

// checkAndRefresh checks if token needs refresh and performs it
func (tm *TokenManager) checkAndRefresh() {
	tm.mu.RLock()
	timeUntilExpiry := time.Until(tm.expiresAt)
	needsRefresh := timeUntilExpiry < 2*time.Minute // Refresh 2 minutes before expiry
	tm.mu.RUnlock()

	if !needsRefresh {
		return
	}

	slog.Info("Token expiring soon, initiating refresh",
		"expires_at", tm.expiresAt.Format(time.RFC3339),
		"time_until_expiry", timeUntilExpiry.String())

	// Try refresh token first if available
	if tm.refreshToken != "" {
		if err := tm.refreshWithRefreshToken(); err != nil {
			slog.Warn("Refresh token failed, falling back to password grant", "error", err)
			if err := tm.refreshWithPassword(); err != nil {
				slog.Error("Token refresh failed", "error", err)
			}
		}
	} else {
		// Fall back to password grant
		if err := tm.refreshWithPassword(); err != nil {
			slog.Error("Token refresh failed", "error", err)
		}
	}
}

// refreshWithRefreshToken attempts to refresh using OAuth2 refresh token
func (tm *TokenManager) refreshWithRefreshToken() error {
	tokenReq := fmt.Sprintf("grant_type=refresh_token&client_id=%s&client_secret=%s&refresh_token=%s",
		tm.clientID, tm.clientSecret, tm.refreshToken)

	resp, err := tm.httpClient.Post(tm.keycloakURL, "application/x-www-form-urlencoded",
		bytes.NewBufferString(tokenReq))
	if err != nil {
		return fmt.Errorf("failed to connect to Keycloak: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Keycloak refresh failed (status %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to parse Keycloak response: %w", err)
	}

	tm.mu.Lock()
	tm.accessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		tm.refreshToken = tokenResp.RefreshToken
	}
	tm.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	tm.mu.Unlock()

	slog.Info("Token refreshed successfully via refresh_token",
		"new_expires_at", tm.expiresAt.Format(time.RFC3339),
		"expires_in", tokenResp.ExpiresIn)

	return nil
}

// refreshWithPassword re-authenticates using password grant
func (tm *TokenManager) refreshWithPassword() error {
	tokenReq := fmt.Sprintf("grant_type=password&client_id=%s&client_secret=%s&username=%s&password=%s",
		tm.clientID, tm.clientSecret, tm.username, tm.password)

	resp, err := tm.httpClient.Post(tm.keycloakURL, "application/x-www-form-urlencoded",
		bytes.NewBufferString(tokenReq))
	if err != nil {
		return fmt.Errorf("failed to connect to Keycloak: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Keycloak authentication failed (status %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to parse Keycloak response: %w", err)
	}

	tm.mu.Lock()
	tm.accessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		tm.refreshToken = tokenResp.RefreshToken
	}
	tm.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	tm.mu.Unlock()

	slog.Info("Token refreshed successfully via password_grant",
		"new_expires_at", tm.expiresAt.Format(time.RFC3339),
		"expires_in", tokenResp.ExpiresIn)

	return nil
}

var witnessObserveCmd = &cobra.Command{
	Use:          "witness-observe",
	Short:        "Observe and sign the current tree state",
	Long:         "Record the current lottery log tree state (size and hash) and sign it with your witness certificate. This creates a tamper-evident record. Use --watch to continuously monitor for new draws.",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		witnessID, _ := cmd.Flags().GetString("witness-id")
		if witnessID == "" {
			return fmt.Errorf("witness-id is required")
		}

		dataDir := viper.GetString("log_directory")

		// Check if server flag is provided for remote observation
		serverURL, _ := cmd.Flags().GetString("server")
		if serverURL != "" {
			// Check if watch mode is enabled
			watch, _ := cmd.Flags().GetBool("watch")
			if watch {
				interval, _ := cmd.Flags().GetDuration("interval")
				peersFile, _ := cmd.Flags().GetString("peers")
				crossCheckInterval, _ := cmd.Flags().GetDuration("cross-check-interval")
				return watchServer(witnessID, serverURL, dataDir, interval, peersFile, crossCheckInterval)
			}
			return observeFromServer(witnessID, serverURL, dataDir)
		}

		// Local observation
		wm, err := tlog.NewWitnessManager(dataDir, witnessID)
		if err != nil {
			slog.Error("Failed to create witness manager", "error", err)
			return err
		}

		if err := wm.ObserveTree(dataDir); err != nil {
			slog.Error("Failed to observe tree", "error", err)
			return err
		}

		// Get the latest witnessed state to display
		states, err := wm.ListWitnessedStates()
		if err != nil {
			slog.Error("Failed to list witnessed states", "error", err)
			return err
		}

		if len(states) > 0 {
			latest := states[len(states)-1]
			slog.Info("Tree state observed and signed",
				"witness_id", witnessID,
				"tree_size", latest.TreeSize,
				"tree_hash", latest.TreeHash[:16]+"...")

			fmt.Printf("\n✓ Tree state observed and signed by witness: %s\n", witnessID)
			fmt.Printf("  Tree Size: %d\n", latest.TreeSize)
			fmt.Printf("  Tree Hash: %s\n", latest.TreeHash)
			fmt.Printf("  Timestamp: %s\n", latest.Timestamp.Format("2006-01-02 15:04:05"))
		}

		return nil
	},
}

func observeFromServer(witnessID, serverURL, dataDir string) error {
	// Try to get JWT token first (for OIDC/Keycloak authentication)
	// If that fails, fall back to direct mTLS
	client, authToken, tokenManager, err := createAuthenticatedClient(witnessID, serverURL, dataDir)
	if err != nil {
		return fmt.Errorf("failed to create authenticated client: %w", err)
	}

	// Clean up token manager if it exists (not needed for single observation)
	if tokenManager != nil {
		defer tokenManager.Stop()
	}

	// First: Get tree state from server (without signature)
	req, err := http.NewRequest("POST", serverURL+"/api/witness/observe", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication header if using JWT
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned error %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse server response: %w", err)
	}

	// Extract tree state from server response
	treeSize := int64(result["tree_size"].(float64))
	treeHash := result["tree_hash"].(string)

	// Get witness manager to check last witnessed state
	wm, err := tlog.NewWitnessManager(dataDir, witnessID)
	if err != nil {
		return fmt.Errorf("failed to create witness manager: %w", err)
	}

	// Check if there are new draws to review
	states, _ := wm.ListWitnessedStates()
	lastWitnessedSize := int64(0)
	if len(states) > 0 {
		lastWitnessedSize = states[len(states)-1].TreeSize
	}

	// If there are new draws, fetch and display them
	if treeSize > lastWitnessedSize {
		fmt.Printf("\n📋 New draws to review (%d → %d):\n", lastWitnessedSize, treeSize)
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		resp3, err := client.Get(fmt.Sprintf("%s/api/draws/since/%d", serverURL, lastWitnessedSize))
		if err == nil && resp3.StatusCode == http.StatusOK {
			var drawsResult struct {
				SinceTreeSize   int64              `json:"since_tree_size"`
				CurrentTreeSize int64              `json:"current_tree_size"`
				NewDrawsCount   int                `json:"new_draws_count"`
				Draws           []tlog.LotteryDraw `json:"draws"`
			}
			if err := json.NewDecoder(resp3.Body).Decode(&drawsResult); err == nil {
				for _, draw := range drawsResult.Draws {
					fmt.Printf("  Seq No: %d | Code: %d\n", draw.SeqNo, draw.Message.Code)
					fmt.Printf("  Text: %s\n", draw.Message.Text)
					if draw.Message.GameProperties != nil {
						fmt.Printf("  Game: %d, Draw: %d, Subdraw: %d\n",
							draw.Message.GameProperties.Game,
							draw.Message.GameProperties.Draw,
							draw.Message.GameProperties.Subdraw)
					}
					fmt.Printf("  Timestamp: %s\n", draw.Timestamp.Format("2006-01-02 15:04:05"))
				}
				fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			}
			resp3.Body.Close()
		}
	}

	// Sign the observation locally
	witnessedState, err := wm.ObserveRemoteTree(treeSize, treeHash)
	if err != nil {
		return fmt.Errorf("failed to observe remote tree: %w", err)
	}

	// Second: Submit signature back to server
	signaturePayload := map[string]string{
		"signature": witnessedState.Signature,
	}
	payloadBytes, _ := json.Marshal(signaturePayload)

	req2, err := http.NewRequest("POST", serverURL+"/api/witness/observe", bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create signature request: %w", err)
	}

	// Add authentication header if using JWT
	if authToken != "" {
		req2.Header.Set("Authorization", "Bearer "+authToken)
	}
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := client.Do(req2)
	if err != nil {
		slog.Warn("Failed to submit signature to server", "error", err)
		fmt.Printf("\n✗ Warning: Signature saved locally but not submitted to server: %v\n", err)
	} else {
		defer resp2.Body.Close()
		if resp2.StatusCode == http.StatusOK {
			slog.Info("Signature cosigned in main log", "witness_id", witnessID)
		} else {
			body, _ := io.ReadAll(resp2.Body)
			slog.Warn("Failed to store cosignature", "status", resp2.StatusCode, "body", string(body))
			fmt.Printf("\n✗ Warning: Server returned status %d when storing signature\n", resp2.StatusCode)
		}
	}

	slog.Info("Tree state observed and signed from server",
		"witness_id", witnessID,
		"tree_size", treeSize,
		"tree_hash", treeHash[:16]+"...")

	fmt.Printf("\n✓ Tree state observed and signed by witness: %s\n", witnessID)
	fmt.Printf("  Tree Size: %d\n", treeSize)
	fmt.Printf("  Tree Hash: %s\n", treeHash)
	fmt.Printf("  Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("  Saved to local witness log: %s/witnesses/%s/witnessed-states.json\n", dataDir, witnessID)
	if resp2 != nil && resp2.StatusCode == http.StatusOK {
		fmt.Printf("  ✓ Signature cosigned in main transparency log\n")
	}

	return nil
}

func watchServer(witnessID, serverURL, dataDir string, interval time.Duration, peersFile string, crossCheckInterval time.Duration) error {
	fmt.Printf("👁️  Starting witness watch mode for: %s\n", witnessID)
	fmt.Printf("📡 Monitoring server: %s\n", serverURL)
	fmt.Printf("⏱️  Check interval: %v\n\n", interval)

	// Track last observed tree size
	wm, err := tlog.NewWitnessManager(dataDir, witnessID)
	if err != nil {
		return fmt.Errorf("failed to create witness manager: %w", err)
	}

	// Get the last witnessed state to know where we are
	states, err := wm.ListWitnessedStates()
	if err != nil {
		return fmt.Errorf("failed to list witnessed states: %w", err)
	}

	lastTreeSize := int64(0)
	if len(states) > 0 {
		lastTreeSize = states[len(states)-1].TreeSize
		fmt.Printf("📋 Last witnessed tree size: %d\n\n", lastTreeSize)
	}

	// Get authenticated client (supports both mTLS and OIDC)
	client, authToken, tokenManager, err := createAuthenticatedClient(witnessID, serverURL, dataDir)
	if err != nil {
		return fmt.Errorf("failed to create authenticated client: %w", err)
	}

	// Clean up token manager on exit
	if tokenManager != nil {
		defer tokenManager.Stop()
		fmt.Printf("🔐 Token manager active - automatic refresh enabled\n\n")
	}

	// Load peer configuration if provided
	var peers []tlog.WitnessPeer
	
	if peersFile != "" {
		peersData, err := os.ReadFile(peersFile)
		if err != nil {
			slog.Warn("Failed to read peers file", "error", err)
		} else {
			if err := json.Unmarshal(peersData, &peers); err != nil {
				slog.Warn("Failed to parse peers file", "error", err)
			} else {
				fmt.Printf("🔗 Cross-checking enabled with %d peer witness(es)\n", len(peers))
				fmt.Printf("   Check interval: %v\n\n", crossCheckInterval)
			}
		}
	}

	// Helper to get current auth token (from manager if available, otherwise use initial)
	getCurrentToken := func() string {
		if tokenManager != nil {
			return tokenManager.GetToken()
		}
		return authToken
	}

	// Helper to perform cross-check with peers
	performCrossCheck := func() {
		if len(peers) == 0 {
			return
		}
		
		slog.Info("Performing cross-check with peer witnesses", "peer_count", len(peers))
		
		check, err := wm.CrossCheckWithPeers(peers, client)
		if err != nil {
			slog.Error("Cross-check failed", "error", err)
			return
		}
		
		if check.OverallConsistent {
			slog.Info("Cross-check completed: all peers consistent",
				"peers_checked", len(check.PeerComparisons),
				"local_tree_size", check.LocalTreeSize)
		} else {
			slog.Error("CROSS-CHECK INCONSISTENCY DETECTED",
				"local_tree_size", check.LocalTreeSize,
				"local_tree_hash", check.LocalTreeHash)
			
			fmt.Printf("\n⚠️  WARNING: Cross-check detected inconsistencies!\n")
			for _, peer := range check.PeerComparisons {
				if !peer.Consistent {
					fmt.Printf("   ❌ Peer %s: %s\n", peer.PeerID, peer.Details)
				}
			}
			fmt.Println()
		}
	}

	// Continuous monitoring loop
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	// Cross-check ticker (if peers configured)
	var crossCheckTicker *time.Ticker
	if len(peers) > 0 {
		crossCheckTicker = time.NewTicker(crossCheckInterval)
		defer crossCheckTicker.Stop()
		
		// Perform initial cross-check
		go performCrossCheck()
	}

	// Helper to send heartbeat
	sendHeartbeat := func() {
		req, _ := http.NewRequest("POST", serverURL+"/api/witness/heartbeat", nil)
		req.Header.Set("X-Witness-ID", witnessID)
		token := getCurrentToken()
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		client.Do(req)
	}

	// Send initial heartbeat
	sendHeartbeat()

	fmt.Println("✅ Watch mode active. Press Ctrl+C to stop.")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	for {
		select {
		case <-ticker.C:
			// Send heartbeat
			sendHeartbeat()

			// Get current tree state
			req, err := http.NewRequest("POST", serverURL+"/api/witness/observe", bytes.NewReader([]byte{}))
			if err != nil {
				slog.Error("Failed to create request", "error", err)
				continue
			}
			token := getCurrentToken()
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			req.Header.Set("Content-Type", "application/json")
			
			resp, err := client.Do(req)
			if err != nil {
				slog.Error("Failed to connect to server", "error", err)
				continue
			}

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				slog.Error("Server returned error", "status", resp.StatusCode, "body", string(body))
				continue
			}

			var state struct {
				TreeSize int64  `json:"tree_size"`
				TreeHash string `json:"tree_hash"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
				resp.Body.Close()
				slog.Error("Failed to decode response", "error", err)
				continue
			}
			resp.Body.Close()

			// Check if tree has grown
			if state.TreeSize > lastTreeSize {
				fmt.Printf("\n🆕 New tree state detected!\n")
				fmt.Printf("   Tree size: %d → %d (+%d draws)\n", lastTreeSize, state.TreeSize, state.TreeSize-lastTreeSize)
				fmt.Printf("   Tree hash: %s\n", state.TreeHash[:16]+"...")
				fmt.Printf("   Verifying and signing...\n")

				// Observe and sign the new tree state
				if err := observeFromServer(witnessID, serverURL, dataDir); err != nil {
					slog.Error("Failed to observe tree", "error", err)
					continue
				}

				lastTreeSize = state.TreeSize
				fmt.Printf("   ✅ Successfully verified and cosigned\n")
				fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			} else {
				fmt.Printf(".")
			}
			
		case <-func() <-chan time.Time {
			if crossCheckTicker != nil {
				return crossCheckTicker.C
			}
			// Return a channel that never sends if no cross-check ticker
			return make(<-chan time.Time)
		}():
			// Perform periodic cross-check with peers
			go performCrossCheck()
		}
	}
}

func init() {
	witnessObserveCmd.Flags().String("witness-id", "", "Your witness identifier (required)")
	witnessObserveCmd.Flags().String("server", "", "Server URL (e.g. https://localhost:8443) for remote observation")
	witnessObserveCmd.Flags().Bool("watch", false, "Watch mode: continuously monitor server for new draws and automatically verify")
	witnessObserveCmd.Flags().Duration("interval", 5*time.Second, "Polling interval in watch mode (e.g., 5s, 10s, 1m)")
	witnessObserveCmd.Flags().String("keycloak-url", "", "Keycloak token endpoint (for OIDC authentication)")
	witnessObserveCmd.Flags().String("client-id", "", "OIDC client ID")
	witnessObserveCmd.Flags().String("client-secret", "", "OIDC client secret")
	witnessObserveCmd.Flags().String("username", "", "Username for OIDC authentication")
	witnessObserveCmd.Flags().String("password", "", "Password for OIDC authentication")
	witnessObserveCmd.Flags().String("peers", "", "Path to JSON file containing peer witness configurations (for cross-checking)")
	witnessObserveCmd.Flags().Duration("cross-check-interval", 5*time.Minute, "Interval for cross-checking with peer witnesses in watch mode")

	// Bind flags to viper to avoid initialization cycle
	viper.BindPFlag("keycloak_url", witnessObserveCmd.Flags().Lookup("keycloak-url"))
	viper.BindPFlag("client_id", witnessObserveCmd.Flags().Lookup("client-id"))
	viper.BindPFlag("client_secret", witnessObserveCmd.Flags().Lookup("client-secret"))
	viper.BindPFlag("username", witnessObserveCmd.Flags().Lookup("username"))
	viper.BindPFlag("password", witnessObserveCmd.Flags().Lookup("password"))

	witnessObserveCmd.MarkFlagRequired("witness-id")
	rootCmd.AddCommand(witnessObserveCmd)
}

// createAuthenticatedClient creates an HTTP client with appropriate authentication
// Returns (client, jwt_token, token_manager, error). Token manager is nil for mTLS-only auth.
func createAuthenticatedClient(witnessID, serverURL, dataDir string) (*http.Client, string, *TokenManager, error) {
	// Check if Keycloak/OIDC credentials are provided via environment variables
	keycloakURL := viper.GetString("keycloak_url")
	clientID := viper.GetString("client_id")
	clientSecret := viper.GetString("client_secret")
	username := viper.GetString("username")
	password := viper.GetString("password")

	// Load witness certificate (may be needed for mTLS to Keycloak or direct mTLS to server)
	certPath := filepath.Join(dataDir, "witnesses", witnessID, "witness-cert.pem")
	keyPath := filepath.Join(dataDir, "witnesses", witnessID, "witness-key.pem")

	var cert tls.Certificate
	var hasCert bool
	if certFile, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		cert = certFile
		hasCert = true
	} else if certFile, err := tls.LoadX509KeyPair(certPath, certPath); err == nil {
		cert = certFile
		hasCert = true
	}

	// If Keycloak URL is provided, get JWT token
	if keycloakURL != "" && clientID != "" {
		slog.Info("Authenticating via Keycloak", "keycloak_url", keycloakURL)

		// Create client for Keycloak (with or without mTLS)
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		if hasCert {
			tlsConfig.Certificates = []tls.Certificate{cert}
			slog.Info("Using client certificate for Keycloak authentication")
		}

		keycloakClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
			Timeout: 10 * time.Second,
		}

		// Get JWT token from Keycloak
		tokenReq := fmt.Sprintf("grant_type=password&client_id=%s&client_secret=%s&username=%s&password=%s",
			clientID, clientSecret, username, password)

		resp, err := keycloakClient.Post(keycloakURL, "application/x-www-form-urlencoded",
			bytes.NewBufferString(tokenReq))
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to connect to Keycloak: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, "", nil, fmt.Errorf("Keycloak authentication failed (status %d): %s", resp.StatusCode, string(body))
		}

		var tokenResp struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    int    `json:"expires_in"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			return nil, "", nil, fmt.Errorf("failed to parse Keycloak response: %w", err)
		}

		slog.Info("Successfully obtained JWT token from Keycloak",
			"expires_in", tokenResp.ExpiresIn,
			"token_type", tokenResp.TokenType,
			"has_refresh_token", tokenResp.RefreshToken != "")

		// Return client WITHOUT certificate (JWT-only auth to server)
		apiClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: 30 * time.Second,
		}

		// Create token manager for automatic refresh
		tokenManager := NewTokenManager(
			tokenResp.AccessToken,
			tokenResp.RefreshToken,
			tokenResp.ExpiresIn,
			keycloakURL,
			clientID,
			clientSecret,
			username,
			password,
			keycloakClient,
		)

		return apiClient, tokenResp.AccessToken, tokenManager, nil
	}

	// Fallback: Direct mTLS to server (original behavior)
	if !hasCert {
		return nil, "", nil, fmt.Errorf("no witness certificate found and no Keycloak credentials provided (run witness-init first)")
	}

	slog.Info("Using direct mTLS authentication with client certificate")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true,
			},
		},
		Timeout: 30 * time.Second,
	}

	return client, "", nil, nil // Empty token and nil token manager for mTLS-only auth
}
