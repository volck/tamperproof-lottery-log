package cmd

import (
	"fmt"
	"log/slog"

	"lottery-tlog/tlog"

	"github.com/spf13/cobra"
)

var witnessListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List all witnessed tree states",
	Long:         "Display all tree states that have been observed and signed by this witness. Each state includes tree size, hash, timestamp, and signature.",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		witnessID, _ := cmd.Flags().GetString("witness-id")
		if witnessID == "" {
			return fmt.Errorf("witness-id is required")
		}

		dataDir := getDataDir()
		wm, err := tlog.NewWitnessManager(dataDir, witnessID)
		if err != nil {
			slog.Error("Failed to create witness manager", "error", err)
			return err
		}

		states, err := wm.ListWitnessedStates()
		if err != nil {
			slog.Error("Failed to list witnessed states", "error", err)
			return err
		}

		if len(states) == 0 {
			fmt.Printf("No witnessed states found for witness: %s\n", witnessID)
			return nil
		}

		fmt.Printf("\nWitnessed States for %s:\n", witnessID)
		fmt.Println("=" + fmt.Sprintf("%*s", len("Witnessed States for "+witnessID), "") + "=")

		for i, state := range states {
			fmt.Printf("\n[%d] Witnessed State\n", i+1)
			fmt.Printf("  Tree Size: %d\n", state.TreeSize)
			fmt.Printf("  Tree Hash: %s\n", state.TreeHash)
			fmt.Printf("  Timestamp: %s\n", state.Timestamp.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Signature: %s...\n", state.Signature[:32])

			// Verify signature
			if err := wm.VerifySignature(state); err != nil {
				fmt.Printf("  ✗ Signature INVALID: %v\n", err)
			} else {
				fmt.Printf("  ✓ Signature verified\n")
			}
		}

		fmt.Printf("\nTotal witnessed states: %d\n", len(states))

		return nil
	},
}

func init() {
	witnessListCmd.Flags().String("witness-id", "", "Your witness identifier (required)")
	witnessListCmd.MarkFlagRequired("witness-id")
}
