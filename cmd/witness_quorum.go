package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"lottery-tlog/tlog"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var witnessQuorumCmd = &cobra.Command{
	Use:   "quorum",
	Short: "Check witness quorum status for the current tree state",
	Long: `Check if enough witnesses have cosigned the current tree state to achieve quorum.

This command is useful for:
- Verifying that sufficient witnesses have validated the log
- Checking quorum before publishing tree hashes
- Confirming distributed consensus among witnesses

Quorum requirements are configurable and can enforce:
- Minimum number of witnesses (e.g., at least 3)
- Threshold percentage (e.g., 2/3 majority = 66.7%)
- Unanimous agreement (100% threshold)`,
	RunE: runWitnessQuorum,
}

var (
	quorumWitnesses  []string
	quorumThreshold  float64
	quorumMinimum    int
	quorumTreeSize   int64
	quorumOutputJSON bool
)

func init() {
	witnessQuorumCmd.Flags().StringSliceVar(&quorumWitnesses, "witnesses", []string{}, "Comma-separated list of known witness IDs (required)")
	witnessQuorumCmd.Flags().Float64Var(&quorumThreshold, "threshold", 0.67, "Quorum threshold (0.0-1.0), e.g., 0.67 for 2/3 majority")
	witnessQuorumCmd.Flags().IntVar(&quorumMinimum, "minimum", 2, "Minimum number of witnesses required")
	witnessQuorumCmd.Flags().Int64Var(&quorumTreeSize, "tree-size", 0, "Specific tree size to check (0 = current/latest)")
	witnessQuorumCmd.Flags().BoolVar(&quorumOutputJSON, "json", false, "Output result as JSON")

	witnessQuorumCmd.MarkFlagRequired("witnesses")
}

func runWitnessQuorum(cmd *cobra.Command, args []string) error {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Get data directory from config
	dataDir := getDataDir()
	if dataDir == "" {
		dataDir = ".lottery-data"
	}

	// Create lottery log
	ll, err := tlog.NewLotteryLog(dataDir, logger)
	if err != nil {
		return fmt.Errorf("failed to create lottery log: %w", err)
	}

	// Determine tree size to check
	var checkTreeSize int64
	var checkTreeHash string

	if quorumTreeSize > 0 {
		checkTreeSize = quorumTreeSize
	} else {
		// Use current tree size
		checkTreeSize, err = ll.GetTreeSize()
		if err != nil {
			return fmt.Errorf("failed to get tree size: %w", err)
		}
	}

	if checkTreeSize == 0 {
		return fmt.Errorf("no draws in log")
	}

	// Get tree hash
	checkTreeHash, err = ll.GetTreeHash(checkTreeSize)
	if err != nil {
		return fmt.Errorf("failed to get tree hash: %w", err)
	}

	// Get cosignatures
	cosignatures, err := ll.GetWitnessCosignatures(checkTreeSize)
	if err != nil {
		return fmt.Errorf("failed to get cosignatures: %w", err)
	}

	// Configure quorum
	config := tlog.QuorumConfig{
		MinWitnesses:    quorumMinimum,
		QuorumThreshold: quorumThreshold,
		KnownWitnesses:  quorumWitnesses,
	}

	// Check quorum
	result, err := tlog.CheckQuorum(cosignatures, config, checkTreeSize, checkTreeHash)
	if err != nil {
		return fmt.Errorf("failed to check quorum: %w", err)
	}

	// Output result
	if quorumOutputJSON {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal result: %w", err)
		}
		fmt.Println(string(data))
	} else {
		printQuorumResult(result, config)
	}

	// Exit with error if quorum not achieved
	if !result.QuorumAchieved {
		return fmt.Errorf("quorum not achieved")
	}

	return nil
}

func printQuorumResult(result *tlog.QuorumResult, config tlog.QuorumConfig) {
	fmt.Println("=== Witness Quorum Status ===")
	fmt.Println()
	fmt.Printf("Tree Size:     %d\n", result.TreeSize)
	fmt.Printf("Tree Hash:     %s\n", result.TreeHash)
	fmt.Println()

	if result.QuorumAchieved {
		fmt.Println("✓ QUORUM ACHIEVED")
	} else {
		fmt.Println("✗ QUORUM NOT ACHIEVED")
	}

	fmt.Println()
	fmt.Printf("Status:        %s\n", result.Details)
	fmt.Printf("Signatures:    %d / %d witnesses (need %d)\n",
		result.ReceivedSignatures,
		len(config.KnownWitnesses),
		result.RequiredSignatures)
	fmt.Printf("Threshold:     %.1f%% (%d witnesses)\n",
		config.QuorumThreshold*100,
		result.RequiredSignatures)
	fmt.Println()

	if len(result.SigningWitnesses) > 0 {
		fmt.Println("Signing Witnesses:")
		for _, witnessID := range result.SigningWitnesses {
			fmt.Printf("  ✓ %s\n", witnessID)
		}
		fmt.Println()
	}

	if len(result.MissingWitnesses) > 0 {
		fmt.Println("Missing Witnesses:")
		for _, witnessID := range result.MissingWitnesses {
			fmt.Printf("  ✗ %s\n", witnessID)
		}
		fmt.Println()
	}

	if len(result.Cosignatures) > 0 {
		fmt.Println("Cosignature Details:")
		for _, cosig := range result.Cosignatures {
			if cosig.TreeSize == result.TreeSize && cosig.TreeHash == result.TreeHash {
				fmt.Printf("  %s: %s...%s (signed at %s)\n",
					cosig.WitnessID,
					cosig.Signature[:8],
					cosig.Signature[len(cosig.Signature)-8:],
					cosig.Timestamp.Format("2006-01-02 15:04:05"))
			}
		}
	}
}

// Helper for parsing witness list from comma-separated string
func parseWitnessList(input string) []string {
	if input == "" {
		return []string{}
	}
	parts := strings.Split(input, ",")
	witnesses := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			witnesses = append(witnesses, trimmed)
		}
	}
	return witnesses
}
