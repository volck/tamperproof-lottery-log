package cmd

import (
	"fmt"
	"log/slog"

	"lottery-tlog/tlog"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var witnessInitCmd = &cobra.Command{
	Use:          "init",
	Short:        "Initialize as a witness with certificate generation",
	Long:         "Generate a cryptographic certificate (RSA key pair) for witnessing lottery draws. This allows you to sign and verify tree states.",
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

		if err := wm.InitCertificate(); err != nil {
			slog.Error("Failed to initialize certificate", "error", err)
			return err
		}

		publicKey, err := wm.ExportPublicKey()
		if err != nil {
			slog.Error("Failed to export public key", "error", err)
			return err
		}

		slog.Info("Witness initialized successfully", "witness_id", witnessID)
		fmt.Printf("\n✓ Witness certificate generated for: %s\n", witnessID)
		fmt.Printf("\nPublic Key (share this with others for verification):\n")
		fmt.Println(publicKey)

		return nil
	},
}

func init() {
	witnessInitCmd.Flags().String("witness-id", "", "Unique identifier for this witness (required)")
	witnessInitCmd.MarkFlagRequired("witness-id")
}
