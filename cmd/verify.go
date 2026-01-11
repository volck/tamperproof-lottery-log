package cmd

import (
	"fmt"
	"lottery-tlog/tlog"

	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the integrity of the lottery draw log",
	Long: `Verify the integrity of the entire transparency log.
	
This command:
- Checks that all draw data matches their stored hashes
- Computes the Merkle tree root hash
- Ensures no tampering has occurred`,
	SilenceUsage: true,
	RunE:         runVerify,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	lotteryLog, err := tlog.NewLotteryLog(getDataDir(), logger)
	if err != nil {
		return fmt.Errorf("failed to create lottery log: %w", err)
	}

	size, err := lotteryLog.GetTreeSize()
	if err != nil {
		return fmt.Errorf("failed to get tree size: %w", err)
	}

	if size == 0 {
		fmt.Println("✓ Log is empty, nothing to verify")
		return nil
	}

	fmt.Printf("Verifying %d draws...\n", size)

	if err := lotteryLog.VerifyIntegrity(); err != nil {
		fmt.Printf("✗ Integrity verification failed: %v\n", err)
		return err
	}

	treeHash, err := lotteryLog.GetTreeHash()
	if err != nil {
		return fmt.Errorf("failed to get tree hash: %w", err)
	}

	fmt.Printf("✓ Integrity verification successful\n")
	fmt.Printf("  Total draws: %d\n", size)
	fmt.Printf("  Tree hash: %x\n", treeHash)

	return nil
}
