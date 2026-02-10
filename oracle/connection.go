//go:build oracle
// +build oracle

package oracle

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/sijms/go-ora/v2"
)

// Config holds Oracle database configuration
type Config struct {
	ConnectionString string        `mapstructure:"connection_string"`
	MaxOpenConns     int           `mapstructure:"max_open_conns"`
	MaxIdleConns     int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime  time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime  time.Duration `mapstructure:"conn_max_idle_time"`
}

// Connection manages the Oracle database connection pool
type Connection struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewConnection creates a new Oracle database connection
func NewConnection(cfg Config, logger *slog.Logger) (*Connection, error) {
	logger.Info("Initializing Oracle database connection",
		"max_open_conns", cfg.MaxOpenConns,
		"max_idle_conns", cfg.MaxIdleConns)

	// Open connection to Oracle using go-ora driver
	db, err := sql.Open("oracle", cfg.ConnectionString)
	if err != nil {
		logger.Error("Failed to open Oracle database", "error", err)
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	} else {
		db.SetMaxOpenConns(25) // Default
	}

	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	} else {
		db.SetMaxIdleConns(5) // Default
	}

	if cfg.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	} else {
		db.SetConnMaxLifetime(5 * time.Minute) // Default
	}

	if cfg.ConnMaxIdleTime > 0 {
		db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	} else {
		db.SetConnMaxIdleTime(30 * time.Second) // Default
	}

	logger.Info("Testing Oracle database connectivity...")
	
	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		logger.Error("Failed to establish Oracle database connection", "error", err)
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Query database version and session info for verification
	var version, user, sid string
	err = db.QueryRowContext(ctx, `
		SELECT banner, user, sys_context('USERENV', 'SID')
		FROM v$version
		WHERE ROWNUM = 1
	`).Scan(&version, &user, &sid)
	if err != nil {
		logger.Warn("Could not retrieve database version info", "error", err)
	} else {
		logger.Info("Oracle connection established successfully",
			"version", version,
			"user", user,
			"session_id", sid)
	}

	return &Connection{
		db:     db,
		logger: logger,
	}, nil
}

// DB returns the underlying database connection
func (c *Connection) DB() *sql.DB {
	return c.db
}

// Close closes the database connection
func (c *Connection) Close() error {
	c.logger.Info("Closing Oracle database connection")
	return c.db.Close()
}

// ExecuteInTransaction executes a function within a transaction
func (c *Connection) ExecuteInTransaction(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			c.logger.Error("Failed to rollback transaction", "error", rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// CheckHealth performs a health check on the database connection
func (c *Connection) CheckHealth(ctx context.Context) error {
	if err := c.db.PingContext(ctx); err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}

	// Check if blockchain table exists and is accessible
	var count int
	err := c.db.QueryRowContext(ctx, `
		SELECT COUNT(*) 
		FROM user_tables 
		WHERE table_name = 'LOTTERY_DRAWS_BLOCKCHAIN'
	`).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check blockchain table: %w", err)
	}

	if count == 0 {
		return fmt.Errorf("blockchain table not found")
	}

	return nil
}
