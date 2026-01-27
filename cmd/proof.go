package cmd

import (
	"github.com/spf13/cobra"
)

// proofCmd represents the parent proof command
var proofCmd = &cobra.Command{
	Use:   "proof",
	Short: "Generate and verify cryptographic proofs for the transparency log",
	Long: `Proof commands for generating and verifying Merkle tree proofs.

The transparency log uses Merkle trees to provide cryptographic proofs of:
- Inclusion: Prove that a specific draw is in the log
- Consistency: Prove that the log has grown append-only without modifications

These proofs allow anyone to verify the integrity of the log without
needing to download the entire dataset.

Available subcommands:
  inclusion         Generate or verify an inclusion proof for a draw
  consistency       Generate or verify a consistency proof between tree states`,
}

func init() {
	rootCmd.AddCommand(proofCmd)

	// Add proof subcommands
	proofCmd.AddCommand(proveInclusionCmd)
	proofCmd.AddCommand(verifyInclusionCmd)
	proofCmd.AddCommand(proveConsistencyCmd)
	proofCmd.AddCommand(verifyConsistencyCmd)
}
