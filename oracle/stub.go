//go:build !oracle
// +build !oracle

package oracle

import (
	"fmt"
	"log/slog"
	"time"

	"lottery-tlog/tlog"
)

// Stub implementations when Oracle support is not compiled in

type Config struct {
	ConnectionString string
	MaxOpenConns     int
	MaxIdleConns     int
	ConnMaxLifetime  time.Duration
	ConnMaxIdleTime  time.Duration
}

type Connection struct {
	logger *slog.Logger
}

func NewConnection(cfg Config, logger *slog.Logger) (*Connection, error) {
	return nil, fmt.Errorf("Oracle support not compiled in. Build with: go build -tags oracle")
}

func (c *Connection) Close() error {
	return nil
}

type LotteryLog struct{}

func NewLotteryLog(conn *Connection, logger *slog.Logger) (*LotteryLog, error) {
	return nil, fmt.Errorf("Oracle support not compiled in. Build with: go build -tags oracle")
}

// Stub methods to implement StorageBackend interface
func (l *LotteryLog) AddDraw(draw tlog.LotteryDraw) error {
	return fmt.Errorf("Oracle support not compiled in")
}

func (l *LotteryLog) GetDraw(index int64) (*tlog.LotteryDraw, error) {
	return nil, fmt.Errorf("Oracle support not compiled in")
}

func (l *LotteryLog) GetTreeSize() (int64, error) {
	return 0, fmt.Errorf("Oracle support not compiled in")
}

func (l *LotteryLog) GetTreeHash(size int64) (string, error) {
	return "", fmt.Errorf("Oracle support not compiled in")
}

func (l *LotteryLog) ListDraws(startIndex, endIndex int64) ([]*tlog.LotteryDraw, error) {
	return nil, fmt.Errorf("Oracle support not compiled in")
}

func (l *LotteryLog) AddWitnessCosignature(cosig tlog.WitnessCosignature) error {
	return fmt.Errorf("Oracle support not compiled in")
}

func (l *LotteryLog) GetLatestWitnessCosignatures() ([]tlog.WitnessCosignature, error) {
	return nil, fmt.Errorf("Oracle support not compiled in")
}

func (l *LotteryLog) VerifyIntegrity() error {
	return fmt.Errorf("Oracle support not compiled in")
}
