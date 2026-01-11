package cmd

import (
	"fmt"
	"log/slog"

	"lottery-tlog/server"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serverCmd = &cobra.Command{
	Use:          "server",
	Short:        "Start the lottery transparency log server",
	Long:         "Start an HTTPS server with mTLS authentication for witnesses. Witnesses connect using their X.509 certificates to observe draws and verify the log.",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		dataDir := viper.GetString("log_directory")
		
		// Load server config
		var serverConfig server.ServerConfig
		if err := viper.UnmarshalKey("server", &serverConfig); err != nil {
			return fmt.Errorf("failed to load server config: %w", err)
		}

		// Create server
		srv, err := server.NewServer(dataDir, slog.Default())
		if err != nil {
			slog.Error("Failed to create server", "error", err)
			return err
		}

		// Start server
		slog.Info("Starting lottery transparency log server...")
		if err := srv.Start(serverConfig); err != nil {
			slog.Error("Server failed", "error", err)
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
}
