package cmd

import (
	"fmt"

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
	lotteryLog, cleanup, err := createLotteryLog()
	if err != nil {
		return fmt.Errorf("failed to create lottery log: %w", err)
	}
	defer cleanup()

	size, err := lotteryLog.GetTreeSize()
	if err != nil {
		return fmt.Errorf("failed to get tree size: %w", err)
	}

	if size == 0 {
		fmt.Println("No draws in the log")
		return nil
	}

	draws, err := lotteryLog.ListDraws(0, size)
	if err != nil {
		return fmt.Errorf("failed to list draws: %w", err)
	}

	fmt.Printf("Total events: %d\n\n", size)

	for i, draw := range draws {
		fmt.Printf("[%d] Seq No: %d | Code: %d\n", i, draw.SeqNo, draw.Message.Code)
		fmt.Printf("    Text: %s\n", draw.Message.Text)
		fmt.Printf("    IP: %s", draw.IP)
		if draw.Message.RemoteIP != "" {
			fmt.Printf(" | Remote: %s", draw.Message.RemoteIP)
		}
		fmt.Println()

		if draw.Message.GameProperties != nil {
			fmt.Printf("    Game: %d, Draw: %d, Subdraw: %d\n",
				draw.Message.GameProperties.Game,
				draw.Message.GameProperties.Draw,
				draw.Message.GameProperties.Subdraw)
		}

		if len(draw.Message.Values) > 0 {
			fmt.Printf("    Values: %v\n", draw.Message.Values)
		}

		if verbose {
			fmt.Printf("    Timestamp: %s\n", draw.Timestamp.Format("2006-01-02 15:04:05"))
			fmt.Printf("    Severity: %s\n", draw.Severity)
			fmt.Printf("    MAC: %s\n", draw.MAC[:16]+"...")
		}
		fmt.Println()
	}

	treeHash, err := lotteryLog.GetTreeHash(size)
	if err == nil && len(treeHash) >= 16 {
		fmt.Printf("Current tree hash: %s\n", treeHash[:16])
	}

	return nil
}
