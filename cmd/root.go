package cmd

import (
"fmt"
"log/slog"
"os"
"strings"
"time"

"lottery-tlog/oracle"
"lottery-tlog/tlog"

"github.com/spf13/cobra"
"github.com/spf13/viper"
)

var (
cfgFile string
dataDir string
logger  *slog.Logger
rootCmd = &cobra.Command{
Use:   "lottery-tlog",
Short: "Tamperproof lottery transparency log",
Long: `A transparency log system for lottery draws using Merkle trees 
and witness cosignatures to ensure tamper-proof auditable records.

Supports both file-based storage and Oracle 19c blockchain tables.`,
}
)

// Execute runs the root command
func Execute() error {
return rootCmd.Execute()
}

func init() {
cobra.OnInitialize(initConfig)

rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")
rootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", "", "data directory (overrides config file)")
}

func initConfig() {
if cfgFile != "" {
viper.SetConfigFile(cfgFile)
} else {
viper.SetConfigName("config")
viper.SetConfigType("yaml")
viper.AddConfigPath(".")
viper.AddConfigPath("$HOME/.lottery-tlog")
}

viper.AutomaticEnv()
viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

if err := viper.ReadInConfig(); err == nil {
fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
}

// Set up logger
level := slog.LevelInfo
logLevelStr := viper.GetString("log_level")

switch strings.ToLower(logLevelStr) {
case "debug":
level = slog.LevelDebug
case "warn", "warning":
level = slog.LevelWarn
case "error":
level = slog.LevelError
}

logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
Level: level,
}))
}

func getDataDir() string {
if dataDir != "" {
return dataDir
}
return viper.GetString("log_directory")
}

func getStorageBackend() string {
backend := viper.GetString("storage_backend")
if backend == "" {
return "file"
}
return backend
}

func createLotteryLog() (*tlog.LotteryLogAdapter, func(), error) {
backend := getStorageBackend()

logger.Info("Initializing lottery log", "backend", backend)

switch backend {
case "oracle":
return createOracleLotteryLog()
case "file", "":
return createFileLotteryLog()
default:
return nil, nil, fmt.Errorf("unsupported storage backend: %s", backend)
}
}

func createFileLotteryLog() (*tlog.LotteryLogAdapter, func(), error) {
ll, err := tlog.NewLotteryLog(getDataDir(), logger)
if err != nil {
return nil, nil, fmt.Errorf("failed to create file-based lottery log: %w", err)
}

adapter := tlog.NewLotteryLogAdapter(ll)
cleanup := func() {}

return adapter, cleanup, nil
}

func createOracleLotteryLog() (*tlog.LotteryLogAdapter, func(), error) {
connStr := viper.GetString("oracle.connection_string")
if connStr == "" {
return nil, nil, fmt.Errorf("oracle.connection_string not configured")
}

oracleConfig := oracle.Config{
ConnectionString: connStr,
MaxOpenConns:     viper.GetInt("oracle.max_open_conns"),
MaxIdleConns:     viper.GetInt("oracle.max_idle_conns"),
ConnMaxLifetime:  viper.GetDuration("oracle.conn_max_lifetime"),
ConnMaxIdleTime:  viper.GetDuration("oracle.conn_max_idle_time"),
}

conn, err := oracle.NewConnection(oracleConfig, logger)
if err != nil {
return nil, nil, fmt.Errorf("failed to connect to Oracle: %w", err)
}

oracleLog, err := oracle.NewLotteryLog(conn, logger)
if err != nil {
conn.Close()
return nil, nil, fmt.Errorf("failed to create Oracle lottery log: %w", err)
}

adapter := tlog.NewLotteryLogAdapter(oracleLog)

cleanup := func() {
if err := conn.Close(); err != nil {
logger.Error("Failed to close Oracle connection", "error", err)
}
}

return adapter, cleanup, nil
}

func formatTimestamp(t time.Time) string {
return t.Format("2006-01-02 15:04:05 MST")
}
