package cmd

import (
	"fmt"
	"log/slog"

	"lottery-tlog/tlog"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var witnessObserveCmd = &cobra.Command{
	Use:          "witness-observe",
	Short:        "Observe and sign the current tree state",
	Long:         "Record the current lottery log tree state (size and hash) and sign it with your witness certificate. This creates a tamper-evident record.",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		witnessID, _ := cmd.Flags().GetString("witness-id")
		if witnessID == "" {
			return fmt.Errorf("witness-id is required")
		}

		dataDir := viper.GetString("log_directory")
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

func init() {
	witnessObserveCmd.Flags().String("witness-id", "", "Your witness identifier (required)")
	witnessObserveCmd.MarkFlagRequired("witness-id")
	rootCmd.AddCommand(witnessObserveCmd)
}
