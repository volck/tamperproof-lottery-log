package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"lottery-tlog/tlog"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var witnessCrossCheckCmd = &cobra.Command{
	Use:   "witness-cross-check",
	Short: "Cross-check witness observations with peer witnesses",
	Long: `Compare your witnessed tree states with other witnesses to ensure consistency.
This detects any attempts to show different log states to different witnesses (fork attacks).`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		witnessID, _ := cmd.Flags().GetString("witness-id")
		if witnessID == "" {
			return fmt.Errorf("witness-id is required")
		}

		peersFile, _ := cmd.Flags().GetString("peers")
		if peersFile == "" {
			return fmt.Errorf("peers file is required")
		}

		dataDir := viper.GetString("log_directory")

		// Load witness manager
		wm, err := tlog.NewWitnessManager(dataDir, witnessID)
		if err != nil {
			slog.Error("Failed to create witness manager", "error", err)
			return err
		}

		// Load peers configuration
		peersData, err := os.ReadFile(peersFile)
		if err != nil {
			slog.Error("Failed to read peers file", "error", err)
			return fmt.Errorf("failed to read peers file: %w", err)
		}

		var peers []tlog.WitnessPeer
		if err := json.Unmarshal(peersData, &peers); err != nil {
			slog.Error("Failed to parse peers file", "error", err)
			return fmt.Errorf("failed to parse peers file: %w", err)
		}

		if len(peers) == 0 {
			return fmt.Errorf("no peers configured in %s", peersFile)
		}

		// Get authenticated client if Keycloak is configured
		serverURL, _ := cmd.Flags().GetString("server")
		var httpClient *http.Client
		if serverURL != "" {
			client, _, tokenManager, err := createAuthenticatedClient(witnessID, serverURL, dataDir)
			if err != nil {
				slog.Warn("Failed to create authenticated client, using unauthenticated", "error", err)
			} else {
				httpClient = client
				if tokenManager != nil {
					defer tokenManager.Stop()
				}
			}
		}

		slog.Info("Starting cross-check with peer witnesses",
			"witness_id", witnessID,
			"peer_count", len(peers))

		// Perform cross-check
		check, err := wm.CrossCheckWithPeers(peers, httpClient)
		if err != nil {
			slog.Error("Cross-check failed", "error", err)
			return err
		}

		// Display results
		fmt.Printf("\n🔍 Witness Cross-Check Results\n")
		fmt.Printf("═════════════════════════════════════════════\n\n")
		fmt.Printf("Local Witness: %s\n", check.LocalWitnessID)
		fmt.Printf("Local Tree Size: %d\n", check.LocalTreeSize)
		fmt.Printf("Local Tree Hash: %s\n", check.LocalTreeHash)
		fmt.Printf("Local Timestamp: %s\n", check.LocalTimestamp.Format("2006-01-02 15:04:05"))
		fmt.Printf("\n")

		fmt.Printf("Peer Comparisons (%d peers):\n", len(check.PeerComparisons))
		fmt.Printf("─────────────────────────────────────────────\n")

		for i, peer := range check.PeerComparisons {
			fmt.Printf("\n%d. Peer: %s\n", i+1, peer.PeerID)
			fmt.Printf("   URL: %s\n", peer.PeerURL)

			if peer.Error != "" {
				fmt.Printf("   ❌ Error: %s\n", peer.Error)
				continue
			}

			fmt.Printf("   Tree Size: %d\n", peer.PeerTreeSize)
			fmt.Printf("   Tree Hash: %s\n", peer.PeerTreeHash)
			fmt.Printf("   Timestamp: %s\n", peer.PeerTimestamp.Format("2006-01-02 15:04:05"))

			if peer.Consistent {
				fmt.Printf("   ✅ Status: Consistent\n")
				fmt.Printf("   Details: %s\n", peer.Details)
			} else {
				fmt.Printf("   ⚠️  Status: INCONSISTENT\n")
				fmt.Printf("   Details: %s\n", peer.Details)
			}
		}

		fmt.Printf("\n─────────────────────────────────────────────\n")
		if check.OverallConsistent {
			fmt.Printf("✅ Overall Status: ALL PEERS CONSISTENT\n")
		} else {
			fmt.Printf("⚠️  Overall Status: INCONSISTENCIES DETECTED\n")
			fmt.Printf("\n⚠️  WARNING: Some peers have inconsistent views of the log!\n")
			fmt.Printf("This may indicate a fork attack or network issues.\n")
		}
		fmt.Printf("\nChecked at: %s\n", check.CheckedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("═════════════════════════════════════════════\n\n")

		// Save results to file
		outputFile, _ := cmd.Flags().GetString("output")
		if outputFile != "" {
			data, err := json.MarshalIndent(check, "", "  ")
			if err != nil {
				slog.Error("Failed to marshal results", "error", err)
			} else {
				if err := os.WriteFile(outputFile, data, 0644); err != nil {
					slog.Error("Failed to write output file", "error", err)
				} else {
					fmt.Printf("Results saved to: %s\n\n", outputFile)
				}
			}
		}

		// Exit with error if inconsistent
		if !check.OverallConsistent {
			return fmt.Errorf("inconsistencies detected during cross-check")
		}

		return nil
	},
}

func init() {
	witnessCrossCheckCmd.Flags().String("witness-id", "", "ID of the witness performing the cross-check")
	witnessCrossCheckCmd.Flags().String("peers", "", "Path to JSON file containing peer witness configurations")
	witnessCrossCheckCmd.Flags().String("server", "", "Optional: Server URL for authentication")
	witnessCrossCheckCmd.Flags().String("output", "", "Optional: Output file for cross-check results (JSON)")

	witnessCrossCheckCmd.MarkFlagRequired("witness-id")
	witnessCrossCheckCmd.MarkFlagRequired("peers")
	rootCmd.AddCommand(witnessCrossCheckCmd)
}
