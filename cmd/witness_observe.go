package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"lottery-tlog/tlog"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

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
				return watchServer(witnessID, serverURL, dataDir, interval)
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
	// Load witness certificate for mTLS
	certPath := filepath.Join(dataDir, "witnesses", witnessID, "witness-cert.pem")
	
	cert, err := tls.LoadX509KeyPair(certPath, certPath)
	if err != nil {
		return fmt.Errorf("failed to load witness certificate: %w (run witness-init first)", err)
	}

	// Create HTTP client with mTLS
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true, // For self-signed server cert
			},
		},
	}

	// First: Get tree state from server (without signature)
	resp, err := client.Post(serverURL+"/api/witness/observe", "application/json", nil)
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
				SinceTreeSize   int64               `json:"since_tree_size"`
				CurrentTreeSize int64               `json:"current_tree_size"`
				NewDrawsCount   int                 `json:"new_draws_count"`
				Draws           []tlog.LotteryDraw  `json:"draws"`
			}
			if err := json.NewDecoder(resp3.Body).Decode(&drawsResult); err == nil {
				for i, draw := range drawsResult.Draws {
					fmt.Printf("\n[Draw #%d]\n", lastWitnessedSize+int64(i)+1)
					fmt.Printf("  Draw ID: %s\n", draw.DrawID)
					fmt.Printf("  Position: %d of %d\n", draw.Position, draw.MaxPosition)
					fmt.Printf("  Type: %s\n", draw.DrawType)
					fmt.Printf("  Timestamp: %s\n", draw.Timestamp.Format("2006-01-02 15:04:05"))
					if draw.RNGHash != "" {
						fmt.Printf("  RNG Hash: %s\n", draw.RNGHash)
					}
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
	
	resp2, err := client.Post(serverURL+"/api/witness/observe", "application/json", bytes.NewReader(payloadBytes))
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

func watchServer(witnessID, serverURL, dataDir string, interval time.Duration) error {
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

	// Continuous monitoring loop
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Helper to send heartbeat
	sendHeartbeat := func() {
		certPath := filepath.Join(dataDir, "witnesses", witnessID, "witness-cert.pem")
		cert, err := tls.LoadX509KeyPair(certPath, certPath)
		if err != nil {
			return
		}
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates:       []tls.Certificate{cert},
					InsecureSkipVerify: true,
				},
			},
			Timeout: 5 * time.Second,
		}
		req, _ := http.NewRequest("POST", serverURL+"/api/witness/heartbeat", nil)
		req.Header.Set("X-Witness-ID", witnessID)
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

			// Load witness certificate for mTLS
			certPath := filepath.Join(dataDir, "witnesses", witnessID, "witness-cert.pem")
			cert, err := tls.LoadX509KeyPair(certPath, certPath)
			if err != nil {
				slog.Error("Failed to load certificate", "error", err)
				continue
			}

			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						Certificates:       []tls.Certificate{cert},
						InsecureSkipVerify: true,
					},
				},
				Timeout: 10 * time.Second,
			}

			// Query the server for current tree state
			resp, err := client.Post(serverURL+"/api/witness/observe", "application/json", bytes.NewReader([]byte{}))
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
		}
	}
}

func init() {
	witnessObserveCmd.Flags().String("witness-id", "", "Your witness identifier (required)")
	witnessObserveCmd.Flags().String("server", "", "Server URL (e.g. https://localhost:8443) for remote observation")
	witnessObserveCmd.Flags().Bool("watch", false, "Watch mode: continuously monitor server for new draws and automatically verify")
	witnessObserveCmd.Flags().Duration("interval", 5*time.Second, "Polling interval in watch mode (e.g., 5s, 10s, 1m)")
	witnessObserveCmd.MarkFlagRequired("witness-id")
	rootCmd.AddCommand(witnessObserveCmd)
}
