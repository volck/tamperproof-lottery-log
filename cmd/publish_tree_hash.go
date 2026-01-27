package cmd

import (
	"fmt"
	"log/slog"

	"lottery-tlog/tlog"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var publishTreeHashCmd = &cobra.Command{
	Use:          "publish-tree-hash",
	Short:        "Publish current tree hash for witnesses",
	Long:         "Display the current tree hash and size for publication to witnesses. This hash should be shared through trusted channels (website, social media, newspaper, etc.) so witnesses can verify they're seeing the same log.",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		dataDir := viper.GetString("log_directory")

		// Use NewLotteryLog to properly create the log
		ll, err := tlog.NewLotteryLog(dataDir, slog.Default())
		if err != nil {
			slog.Error("Failed to create lottery log", "error", err)
			return err
		}

		treeSize, err := ll.GetTreeSize()
		if err != nil {
			slog.Error("Failed to get tree size", "error", err)
			return err
		}

		if treeSize == 0 {
			return fmt.Errorf("no draws in the log yet")
		}

		treeHash, err := ll.GetTreeHash(treeSize)

		hashHex := fmt.Sprintf("%x", treeHash[:])

		slog.Info("Publishing tree hash", "tree_size", treeSize, "tree_hash", hashHex[:16]+"...")

		fmt.Printf("\n===========================================\n")
		fmt.Printf("  LOTTERY LOG TREE HASH - FOR PUBLICATION\n")
		fmt.Printf("===========================================\n\n")
		fmt.Printf("Tree Size: %d draws\n", treeSize)
		fmt.Printf("Tree Hash: %s\n\n", hashHex)
		fmt.Printf("Publish this hash through trusted channels:\n")
		fmt.Printf("  - Company website\n")
		fmt.Printf("  - Social media accounts\n")
		fmt.Printf("  - Official announcements\n")
		fmt.Printf("  - Newspaper publication\n")
		fmt.Printf("  - Blockchain timestamp service\n\n")
		fmt.Printf("Witnesses should observe this hash using:\n")
		fmt.Printf("  lottery-tlog witness observe --witness-id <id>\n")
		fmt.Printf("===========================================\n\n")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(publishTreeHashCmd)
}
