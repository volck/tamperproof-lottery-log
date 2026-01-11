package cmd

import (
	"fmt"
	"log/slog"

	"lottery-tlog/tlog"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var witnessVerifyConsistencyCmd = &cobra.Command{
	Use:          "witness-verify-consistency",
	Short:        "Verify consistency between witnessed states",
	Long:         "Verify that the tree has grown consistently between two witnessed states. This detects if the log has been tampered with or rolled back.",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		witnessID, _ := cmd.Flags().GetString("witness-id")
		if witnessID == "" {
			return fmt.Errorf("witness-id is required")
		}

		oldIndex, _ := cmd.Flags().GetInt("old-index")
		newIndex, _ := cmd.Flags().GetInt("new-index")

		dataDir := viper.GetString("log_directory")
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
			return fmt.Errorf("no witnessed states found")
		}

		if oldIndex < 1 || oldIndex > len(states) {
			return fmt.Errorf("old-index out of range (1-%d)", len(states))
		}

		if newIndex < 1 || newIndex > len(states) {
			return fmt.Errorf("new-index out of range (1-%d)", len(states))
		}

		oldState := states[oldIndex-1]
		newState := states[newIndex-1]

		if oldState.TreeSize >= newState.TreeSize {
			return fmt.Errorf("old state must have smaller tree size than new state")
		}

		slog.Info("Verifying consistency between witnessed states",
			"old_tree_size", oldState.TreeSize,
			"new_tree_size", newState.TreeSize)

		if err := wm.VerifyConsistency(oldState, newState, dataDir); err != nil {
			slog.Error("Consistency verification failed", "error", err)
			fmt.Printf("\n✗ CONSISTENCY CHECK FAILED\n")
			fmt.Printf("  The tree may have been tampered with!\n")
			fmt.Printf("  Error: %v\n", err)
			return err
		}

		slog.Info("Consistency verified successfully")
		fmt.Printf("\n✓ CONSISTENCY VERIFIED\n")
		fmt.Printf("  Tree grew consistently from size %d to %d\n", oldState.TreeSize, newState.TreeSize)
		fmt.Printf("  Old tree hash: %s\n", oldState.TreeHash)
		fmt.Printf("  New tree hash: %s\n", newState.TreeHash)

		return nil
	},
}

func init() {
	witnessVerifyConsistencyCmd.Flags().String("witness-id", "", "Your witness identifier (required)")
	witnessVerifyConsistencyCmd.Flags().Int("old-index", 0, "Index of older witnessed state (1-based, required)")
	witnessVerifyConsistencyCmd.Flags().Int("new-index", 0, "Index of newer witnessed state (1-based, required)")

	witnessVerifyConsistencyCmd.MarkFlagRequired("witness-id")
	witnessVerifyConsistencyCmd.MarkFlagRequired("old-index")
	witnessVerifyConsistencyCmd.MarkFlagRequired("new-index")

	rootCmd.AddCommand(witnessVerifyConsistencyCmd)
}
