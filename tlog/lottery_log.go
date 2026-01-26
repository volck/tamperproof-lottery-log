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

// GameProperties represents game identifiers for lottery draws
type GameProperties struct {
	Game    int `json:"game"`
	Draw    int `json:"draw"`
	Subdraw int `json:"subdraw"`
}

// DrawParameters represents parameters for random number generation
type DrawParameters struct {
	LowBound        int   `json:"low_bound"`
	HighBound       int   `json:"high_bound"`
	PutBack         bool  `json:"put_back"`
	UseDistribution bool  `json:"use_distribution"`
	Distribution    []int `json:"distribution,omitempty"`
}

// DrawChecks represents binary and config checksums
type DrawChecks struct {
	BinaryChecksum  string    `json:"binary_checksum"`
	BinaryTimestamp time.Time `json:"binary_timestamp"`
	ConfigFilename  string    `json:"config_filename"`
	ConfigTimestamp time.Time `json:"config_timestamp"`
}

// UnmarshalJSON implements custom JSON unmarshaling for DrawChecks
// to handle multiple timestamp formats
func (dc *DrawChecks) UnmarshalJSON(data []byte) error {
	type Alias DrawChecks
	aux := &struct {
		BinaryTimestamp string `json:"binary_timestamp"`
		ConfigTimestamp string `json:"config_timestamp"`
		*Alias
	}{
		Alias: (*Alias)(dc),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Try multiple timestamp formats
	formats := []string{
		time.RFC3339,                   // 2006-01-02T15:04:05Z07:00
		time.RFC3339Nano,               // 2006-01-02T15:04:05.999999999Z07:00
		"2006-01-02T15:04:05.999-0700", // 2025-10-15T09:21:17.318+0200
		"2006-01-02T15:04:05-0700",     // 2025-10-15T09:21:17+0200
	}

	var err error
	for _, format := range formats {
		dc.BinaryTimestamp, err = time.Parse(format, aux.BinaryTimestamp)
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("unable to parse binary_timestamp %q: %w", aux.BinaryTimestamp, err)
	}

	for _, format := range formats {
		dc.ConfigTimestamp, err = time.Parse(format, aux.ConfigTimestamp)
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("unable to parse config_timestamp %q: %w", aux.ConfigTimestamp, err)
	}

	return nil
}

// Message represents the lottery event message with different structures based on code
type Message struct {
	Code            int             `json:"code"`
	Text            string          `json:"text"`
	RemoteIP        string          `json:"remote_ip,omitempty"`
	Values          []int           `json:"values,omitempty"`
	String          string          `json:"string,omitempty"`
	Parameters      *DrawParameters `json:"parameters,omitempty"`
	Checks          *DrawChecks     `json:"checks,omitempty"`
	*GameProperties `json:",omitempty,inline"`
}

// LotteryDraw represents a single lottery draw event following the log schema
type LotteryDraw struct {
	Timestamp time.Time `json:"timestamp"`
	SeqNo     int       `json:"seqno"`
	IP        string    `json:"ip"`
	Severity  string    `json:"severity"`
	Message   Message   `json:"message"`
	MAC       string    `json:"mac"`
}

// UnmarshalJSON implements custom JSON unmarshaling for LotteryDraw
// to handle multiple timestamp formats (+0200, +02:00, Z)
func (ld *LotteryDraw) UnmarshalJSON(data []byte) error {
	type Alias LotteryDraw
	aux := &struct {
		Timestamp string `json:"timestamp"`
		*Alias
	}{
		Alias: (*Alias)(ld),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Try multiple timestamp formats
	formats := []string{
		time.RFC3339,                   // 2006-01-02T15:04:05Z07:00
		time.RFC3339Nano,               // 2006-01-02T15:04:05.999999999Z07:00
		"2006-01-02T15:04:05.999-0700", // 2025-10-15T09:21:17.318+0200
		"2006-01-02T15:04:05-0700",     // 2025-10-15T09:21:17+0200
	}

	var err error
	for _, format := range formats {
		ld.Timestamp, err = time.Parse(format, aux.Timestamp)
		if err == nil {
			return nil
		}
	}

	return fmt.Errorf("unable to parse timestamp %q: %w", aux.Timestamp, err)
}

// WitnessCosignature represents a witness's signature on a tree state
type WitnessCosignature struct {
	WitnessID string    `json:"witness_id"`
	TreeSize  int64     `json:"tree_size"`
	TreeHash  string    `json:"tree_hash"`
	Timestamp time.Time `json:"timestamp"`
	Signature string    `json:"signature"`
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
	l.logger.Info("Adding lottery draw",
		"seqno", draw.SeqNo,
		"code", draw.Message.Code,
		"timestamp", draw.Timestamp)

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

// GetTreeHashRaw returns the current Merkle tree root hash as raw bytes
func (l *LotteryLog) GetTreeHashRaw() (tlog.Hash, error) {
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

// AddWitnessCosignature stores a witness's signature for a specific tree state
func (l *LotteryLog) AddWitnessCosignature(cosig WitnessCosignature) error {
	cosigPath := filepath.Join(l.dataDir, fmt.Sprintf("cosignatures-%d.json", cosig.TreeSize))

	var cosignatures []WitnessCosignature

	// Load existing cosignatures if file exists
	if data, err := os.ReadFile(cosigPath); err == nil {
		if err := json.Unmarshal(data, &cosignatures); err != nil {
			return fmt.Errorf("failed to parse existing cosignatures: %w", err)
		}
	}

	// Check if this witness already signed this tree state
	for _, existing := range cosignatures {
		if existing.WitnessID == cosig.WitnessID {
			return fmt.Errorf("witness %s already cosigned tree size %d", cosig.WitnessID, cosig.TreeSize)
		}
	}

	// Append new cosignature
	cosignatures = append(cosignatures, cosig)

	// Save back to disk
	data, err := json.MarshalIndent(cosignatures, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cosignatures: %w", err)
	}

	if err := os.WriteFile(cosigPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write cosignatures file: %w", err)
	}

	l.logger.Info("Witness cosignature stored",
		"witness_id", cosig.WitnessID,
		"tree_size", cosig.TreeSize,
		"tree_hash", cosig.TreeHash[:16]+"...")

	return nil
}

// GetWitnessCosignatures retrieves all witness signatures for a specific tree state
func (l *LotteryLog) GetWitnessCosignatures(treeSize int64) ([]WitnessCosignature, error) {
	cosigPath := filepath.Join(l.dataDir, fmt.Sprintf("cosignatures-%d.json", treeSize))

	data, err := os.ReadFile(cosigPath)
	if os.IsNotExist(err) {
		return []WitnessCosignature{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read cosignatures: %w", err)
	}

	var cosignatures []WitnessCosignature
	if err := json.Unmarshal(data, &cosignatures); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cosignatures: %w", err)
	}

	return cosignatures, nil
}

// GetLatestWitnessCosignatures retrieves all witness signatures for the current tree state
func (l *LotteryLog) GetLatestWitnessCosignatures() ([]WitnessCosignature, error) {
	size, err := l.GetTreeSize()
	if err != nil {
		return nil, fmt.Errorf("failed to get tree size: %w", err)
	}

	if size == 0 {
		return []WitnessCosignature{}, nil
	}

	return l.GetWitnessCosignatures(size)
}

// GetTreeHash returns the tree hash for a given tree size
func (l *LotteryLog) GetTreeHash(size int64) (string, error) {
	if size == 0 {
		return "", nil
	}

	hr := &hashReader{dataDir: l.dataDir, size: size}
	th, err := tlog.TreeHash(size, hr)
	if err != nil {
		return "", fmt.Errorf("failed to compute tree hash: %w", err)
	}

	return fmt.Sprintf("%x", th[:]), nil
}

// ListDraws returns draws in a specified range
func (l *LotteryLog) ListDraws(startIndex, endIndex int64) ([]*LotteryDraw, error) {
	draws := make([]*LotteryDraw, 0, endIndex-startIndex)
	for i := startIndex; i < endIndex; i++ {
		draw, err := l.GetDraw(i)
		if err != nil {
			return nil, fmt.Errorf("failed to get draw %d: %w", i, err)
		}
		draws = append(draws, draw)
	}
	return draws, nil
}
