package cmd

import (
	"fmt"
	"log/slog"
	"lottery-tlog/tlog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var witnessWatchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Start witness file watcher to monitor and validate log files",
	Long: `Start a witness file watcher that monitors a directory for log file changes.
When files are modified, the watcher:
1. Validates HMAC signatures on all log entries
2. Queries the server for current tree state
3. Creates a witnessed state and signs it
4. Submits cosignature to the server if validation passes

This is useful for witnesses that receive log files from an external source
(e.g., via rsync, network mount, or log receiver) and need to validate and
acknowledge them automatically.`,
	RunE: runWitnessWatch,
}

var (
	watchDir        string
	keyFile         string
	witnessID       string
	serverURL       string
	useLocalBackend bool
)

func init() {
	witnessWatchCmd.Flags().StringVar(&watchDir, "watch-dir", "", "Directory to watch for log file changes (required)")
	witnessWatchCmd.Flags().StringVar(&keyFile, "key-file", "", "Path to key file containing HMAC key (required)")
	witnessWatchCmd.Flags().StringVar(&witnessID, "witness-id", "", "Witness identifier (required)")
	witnessWatchCmd.Flags().StringVar(&serverURL, "server-url", "", "Server URL to query for tree state")
	witnessWatchCmd.Flags().BoolVar(&useLocalBackend, "use-local-backend", false, "Use local file backend instead of HTTP API")

	witnessWatchCmd.MarkFlagRequired("watch-dir")
	witnessWatchCmd.MarkFlagRequired("key-file")
	witnessWatchCmd.MarkFlagRequired("witness-id")
}

func runWitnessWatch(cmd *cobra.Command, args []string) error {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Get data directory from config
	dataDir := getDataDir()
	if dataDir == "" {
		dataDir = ".lottery-data"
	}

	// Create witness manager
	witnessManager, err := tlog.NewWitnessManager(dataDir, witnessID)
	if err != nil {
		return fmt.Errorf("failed to create witness manager: %w", err)
	}

	// Load or initialize witness certificate
	if err := witnessManager.LoadCertificate(); err != nil {
		logger.Warn("Certificate not found, initializing new certificate", "error", err)
		if err := witnessManager.InitCertificate(); err != nil {
			return fmt.Errorf("failed to initialize certificate: %w", err)
		}
		logger.Info("New witness certificate created", "witness_id", witnessID)
	} else {
		logger.Info("Loaded existing witness certificate", "witness_id", witnessID)
	}

	// Create watcher config
	watcherConfig := tlog.WitnessWatcherConfig{
		WatchDir:       watchDir,
		KeyFile:        keyFile,
		WitnessManager: witnessManager,
		ServerURL:      serverURL,
		Logger:         logger,
	}

	// Optionally use local backend
	if useLocalBackend {
		ll, err := tlog.NewLotteryLog(dataDir, logger)
		if err != nil {
			return fmt.Errorf("failed to create lottery log backend: %w", err)
		}
		watcherConfig.LogBackend = ll
		logger.Info("Using local file backend for tree state queries")
	}

	// Create and start watcher
	watcher, err := tlog.NewWitnessWatcher(watcherConfig)
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}

	if err := watcher.Start(); err != nil {
		return fmt.Errorf("failed to start watcher: %w", err)
	}

	logger.Info("Witness watcher started successfully",
		"watch_dir", watchDir,
		"witness_id", witnessID,
		"key_file", keyFile,
	)

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan

	logger.Info("Shutting down witness watcher...")
	if err := watcher.Stop(); err != nil {
		return fmt.Errorf("error stopping watcher: %w", err)
	}

	logger.Info("Witness watcher stopped")
	return nil
}
