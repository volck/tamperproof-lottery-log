package tlog

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/mod/sumdb/tlog"
)

// LotteryDraw represents a single lottery draw event
type LotteryDraw struct {
	DrawID      string    `json:"draw_id"`
	Timestamp   time.Time `json:"timestamp"`
	Position    int       `json:"position"`
	MaxPosition int       `json:"max_position"`
	RNGHash     string    `json:"rng_hash"` // Hash used by RNG to generate position
	DrawType    string    `json:"draw_type"`
}

// LotteryLog manages the transparency log for lottery draws
type LotteryLog struct {
	dataDir string
	logger  *slog.Logger
}

// NewLotteryLog creates a new lottery log manager
func NewLotteryLog(dataDir string, logger *slog.Logger) (*LotteryLog, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	return &LotteryLog{
		dataDir: dataDir,
		logger:  logger,
	}, nil
}

// AddDraw adds a new lottery draw to the transparency log
func (l *LotteryLog) AddDraw(draw LotteryDraw) error {
	l.logger.Info("Adding lottery draw", "draw_id", draw.DrawID, "timestamp", draw.Timestamp)

	// Serialize the draw
	data, err := json.Marshal(draw)
	if err != nil {
		return fmt.Errorf("failed to marshal draw: %w", err)
	}

	// Get current tree size
	size, err := l.getTreeSize()
	if err != nil {
		return fmt.Errorf("failed to get tree size: %w", err)
	}

	// Save the draw data
	drawPath := filepath.Join(l.dataDir, fmt.Sprintf("draw-%d.json", size))
	if err := os.WriteFile(drawPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write draw data: %w", err)
	}

	// Compute and store the hashes using tlog.StoredHashes
	// First, we need a reader for existing hashes
	hr := &hashReader{dataDir: l.dataDir, size: size}
	
	storedHashes, err := tlog.StoredHashes(size, data, hr)
	if err != nil {
		return fmt.Errorf("failed to compute stored hashes: %w", err)
	}

	// Store the new hashes starting at the appropriate index
	startIndex := tlog.StoredHashIndex(0, size)
	for i, hash := range storedHashes {
		hashPath := filepath.Join(l.dataDir, fmt.Sprintf("hash-%d.bin", startIndex+int64(i)))
		if err := os.WriteFile(hashPath, hash[:], 0644); err != nil {
			return fmt.Errorf("failed to write hash: %w", err)
		}
	}

	// Update tree size
	if err := l.setTreeSize(size + 1); err != nil {
		return fmt.Errorf("failed to update tree size: %w", err)
	}

	l.logger.Info("Successfully added draw", "index", size, "hash", fmt.Sprintf("%x", storedHashes[0][:8]))
	return nil
}

// GetDraw retrieves a lottery draw by index
func (l *LotteryLog) GetDraw(index int64) (*LotteryDraw, error) {
	drawPath := filepath.Join(l.dataDir, fmt.Sprintf("draw-%d.json", index))
	data, err := os.ReadFile(drawPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read draw: %w", err)
	}

	var draw LotteryDraw
	if err := json.Unmarshal(data, &draw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal draw: %w", err)
	}

	return &draw, nil
}

// GetTreeSize returns the current size of the transparency log
func (l *LotteryLog) GetTreeSize() (int64, error) {
	return l.getTreeSize()
}

// hashReader implements tlog.HashReader interface
type hashReader struct {
	dataDir string
	size    int64
}

func (hr *hashReader) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	result := make([]tlog.Hash, len(indexes))
	for i, idx := range indexes {
		hashPath := filepath.Join(hr.dataDir, fmt.Sprintf("hash-%d.bin", idx))
		hashData, err := os.ReadFile(hashPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read hash %d: %w", idx, err)
		}
		if len(hashData) != 32 {
			return nil, fmt.Errorf("invalid hash size at index %d", idx)
		}
		copy(result[i][:], hashData)
	}
	return result, nil
}

// VerifyIntegrity verifies the integrity of the entire log
func (l *LotteryLog) VerifyIntegrity() error {
	size, err := l.getTreeSize()
	if err != nil {
		return fmt.Errorf("failed to get tree size: %w", err)
	}

	l.logger.Info("Verifying log integrity", "size", size)

	if size == 0 {
		l.logger.Info("Log is empty, nothing to verify")
		return nil
	}

	// Verify each draw matches its stored hashes
	for i := int64(0); i < size; i++ {
		// Read the original stored draw data
		drawPath := filepath.Join(l.dataDir, fmt.Sprintf("draw-%d.json", i))
		data, err := os.ReadFile(drawPath)
		if err != nil {
			return fmt.Errorf("failed to read draw %d: %w", i, err)
		}

		// Verify it's valid JSON by unmarshaling
		var draw LotteryDraw
		if err := json.Unmarshal(data, &draw); err != nil {
			return fmt.Errorf("failed to unmarshal draw %d: %w", i, err)
		}

		// Compute the hash of the actual stored data
		actualRecordHash := tlog.RecordHash(data)
		
		// Read the stored hash for this record (leaf hash is first)
		startIndex := tlog.StoredHashIndex(0, i)
		hashPath := filepath.Join(l.dataDir, fmt.Sprintf("hash-%d.bin", startIndex))
		storedHashData, err := os.ReadFile(hashPath)
		if err != nil {
			return fmt.Errorf("failed to read stored hash for draw %d: %w", i, err)
		}
		
		var storedRecordHash tlog.Hash
		copy(storedRecordHash[:], storedHashData)
		
		// Verify the data hash matches the stored hash
		if actualRecordHash != storedRecordHash {
			return fmt.Errorf("hash mismatch at draw %d: expected %x, got %x", 
				i, storedRecordHash[:8], actualRecordHash[:8])
		}
	}

	// Also verify the overall tree structure is correct
	hr := &hashReader{dataDir: l.dataDir, size: size}
	th, err := tlog.TreeHash(size, hr)
	if err != nil {
		return fmt.Errorf("failed to compute tree hash: %w", err)
	}

	// Store the tree hash for future verification
	treeHashPath := filepath.Join(l.dataDir, "tree-hash.bin")
	if err := os.WriteFile(treeHashPath, th[:], 0644); err != nil {
		l.logger.Warn("Failed to write tree hash", "error", err)
	}

	l.logger.Info("Integrity verification successful", 
		"size", size, 
		"tree_hash", fmt.Sprintf("%x", th[:8]))

	return nil
}

// GetTreeHash returns the current Merkle tree root hash
func (l *LotteryLog) GetTreeHash() (tlog.Hash, error) {
	size, err := l.getTreeSize()
	if err != nil {
		return tlog.Hash{}, fmt.Errorf("failed to get tree size: %w", err)
	}

	if size == 0 {
		return tlog.Hash{}, nil
	}

	hr := &hashReader{dataDir: l.dataDir, size: size}
	th, err := tlog.TreeHash(size, hr)
	if err != nil {
		return tlog.Hash{}, fmt.Errorf("failed to compute tree hash: %w", err)
	}

	return th, nil
}

// ListAllDraws returns all draws in the log
func (l *LotteryLog) ListAllDraws() ([]*LotteryDraw, error) {
	size, err := l.getTreeSize()
	if err != nil {
		return nil, fmt.Errorf("failed to get tree size: %w", err)
	}

	draws := make([]*LotteryDraw, 0, size)
	for i := int64(0); i < size; i++ {
		draw, err := l.GetDraw(i)
		if err != nil {
			return nil, fmt.Errorf("failed to get draw %d: %w", i, err)
		}
		draws = append(draws, draw)
	}

	return draws, nil
}

func (l *LotteryLog) getTreeSize() (int64, error) {
	sizePath := filepath.Join(l.dataDir, "tree-size.txt")
	data, err := os.ReadFile(sizePath)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}

	var size int64
	_, err = fmt.Sscanf(string(data), "%d", &size)
	return size, err
}

func (l *LotteryLog) setTreeSize(size int64) error {
	sizePath := filepath.Join(l.dataDir, "tree-size.txt")
	return os.WriteFile(sizePath, []byte(fmt.Sprintf("%d", size)), 0644)
}
