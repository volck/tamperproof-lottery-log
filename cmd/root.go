package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile   string
	dataDir   string
	logger    *slog.Logger
	rootCmd   = &cobra.Command{
		Use:   "lottery-tlog",
		Short: "Lottery draw transparency log manager",
		Long: `A proof of concept for using transparency logs to maintain 
integrity of lottery draw records.

Uses golang.org/x/mod/sumdb/tlog to create a verifiable, 
append-only log of all lottery draws.`,
	}
)

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")
	rootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", "", "data directory (default is .lottery-data)")
	
	viper.BindPFlag("log_directory", rootCmd.PersistentFlags().Lookup("data-dir"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName("config")
	}

	viper.SetDefault("log_directory", ".lottery-data")
	viper.SetDefault("log_level", "info")

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	// Initialize logger
	logLevel := slog.LevelInfo
	switch viper.GetString("log_level") {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}

	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
}

func getDataDir() string {
	if dataDir != "" {
		return dataDir
	}
	return viper.GetString("log_directory")
}
