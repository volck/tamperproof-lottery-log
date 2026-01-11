package cmd

import (
	"fmt"
	"lottery-tlog/tlog"

	"github.com/spf13/cobra"
)

var (
	verbose bool
)

var listCmd = &cobra.Command{
	Use:          "list",
	Short:        "List all lottery draws in the log",
	Long:         `Display all lottery draws stored in the transparency log.`,
	SilenceUsage: true,
	RunE:         runList,
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed information")
}

func runList(cmd *cobra.Command, args []string) error {
	lotteryLog, err := tlog.NewLotteryLog(getDataDir(), logger)
	if err != nil {
		return fmt.Errorf("failed to create lottery log: %w", err)
	}

	size, err := lotteryLog.GetTreeSize()
	if err != nil {
		return fmt.Errorf("failed to get tree size: %w", err)
	}

	if size == 0 {
		fmt.Println("No draws in the log")
		return nil
	}

	draws, err := lotteryLog.ListAllDraws()
	if err != nil {
		return fmt.Errorf("failed to list draws: %w", err)
	}

	fmt.Printf("Total draws: %d\n\n", size)

	for i, draw := range draws {
		fmt.Printf("[%d] Draw ID: %s\n", i, draw.DrawID)
		fmt.Printf("    Type: %s\n", draw.DrawType)
		fmt.Printf("    Position: %d of %d\n", draw.Position, draw.MaxPosition)
		if draw.RNGHash != "" {
			fmt.Printf("    RNG Hash: %s\n", draw.RNGHash)
		}
		if verbose {
			fmt.Printf("    Timestamp: %s\n", draw.Timestamp.Format("2006-01-02 15:04:05"))
		}
		fmt.Println()
	}

	treeHash, err := lotteryLog.GetTreeHash()
	if err == nil {
		fmt.Printf("Current tree hash: %x\n", treeHash[:16])
	}

	return nil
}
