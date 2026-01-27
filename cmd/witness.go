package cmd

import (
	"github.com/spf13/cobra"
)

// witnessCmd represents the parent witness command
var witnessCmd = &cobra.Command{
	Use:   "witness",
	Short: "Witness operations for transparency log verification",
	Long: `Witness commands for independent verification of the lottery transparency log.

Witnesses are independent parties that observe and cryptographically sign tree states
to provide additional security guarantees. They help detect forks, rollbacks, and
other malicious behavior by the log server.

Available subcommands:
  init          Initialize a new witness with certificate generation
  observe       Observe and sign the current tree state
  watch         Watch a directory for log file changes and validate automatically
  list          List all witnessed states
  verify-consistency  Verify consistency between two witnessed states
  cross-check   Cross-check observations with peer witnesses
  quorum        Check quorum status for a tree state`,
}

func init() {
	rootCmd.AddCommand(witnessCmd)

	// Add all witness subcommands
	witnessCmd.AddCommand(witnessInitCmd)
	witnessCmd.AddCommand(witnessObserveCmd)
	witnessCmd.AddCommand(witnessWatchCmd)
	witnessCmd.AddCommand(witnessListCmd)
	witnessCmd.AddCommand(witnessVerifyConsistencyCmd)
	witnessCmd.AddCommand(witnessCrossCheckCmd)
	witnessCmd.AddCommand(witnessQuorumCmd)
}
