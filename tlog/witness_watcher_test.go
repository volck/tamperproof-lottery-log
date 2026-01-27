package tlog

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWitnessWatcher tests the file watcher functionality
func TestWitnessWatcher(t *testing.T) {
	// Create temporary directories
	tempDir := t.TempDir()
	watchDir := filepath.Join(tempDir, "watch")
	witnessDir := filepath.Join(tempDir, "witness")
	
	if err := os.MkdirAll(watchDir, 0755); err != nil {
		t.Fatalf("Failed to create watch directory: %v", err)
	}

	// Create a test key
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	keyFile := filepath.Join(tempDir, "key.json")
	keyContent := `{"logs": {"key": "` + testKey + `"}}`
	if err := os.WriteFile(keyFile, []byte(keyContent), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	// Create witness manager
	witnessManager, err := NewWitnessManager(witnessDir, "test-witness")
	if err != nil {
		t.Fatalf("Failed to create witness manager: %v", err)
	}

	// Initialize witness certificate
	if err := witnessManager.InitCertificate(); err != nil {
		t.Fatalf("Failed to initialize witness certificate: %v", err)
	}

	// Create mock log backend
	mockBackend := &MockLogBackend{
		treeSize: 10,
		treeHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	// Create watcher
	watcher, err := NewWitnessWatcher(WitnessWatcherConfig{
		WatchDir:       watchDir,
		KeyFile:        keyFile,
		WitnessManager: witnessManager,
		LogBackend:     mockBackend,
	})
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	// Start watching
	if err := watcher.Start(); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer watcher.Stop()

	// Create a valid log entry
	entry := `{ "timestamp": "2024-06-24T07:41:59.049+0200", "seqno": 1, "ip": "172.21.0.69", "severity": "harmless", "message": { "code": 303, "text": "Test entry" }, "mac": "0000000000000000000000000000000000000000000000000000000000000000" }`
	
	// Compute valid MAC
	mac := computeValidMAC(entry, testKey)
	entry = strings.Replace(entry, "0000000000000000000000000000000000000000000000000000000000000000", mac, 1)

	// Write log file (this should trigger validation)
	logFile := filepath.Join(watchDir, "test.log")
	if err := os.WriteFile(logFile, []byte(entry), 0644); err != nil {
		t.Fatalf("Failed to write log file: %v", err)
	}

	// Wait for processing
	time.Sleep(2 * time.Second)

	// Verify that witness signed the state
	states, err := witnessManager.ListWitnessedStates()
	if err != nil {
		t.Fatalf("Failed to list witnessed states: %v", err)
	}

	if len(states) == 0 {
		t.Errorf("Expected at least one witnessed state, got none")
	} else {
		lastState := states[len(states)-1]
		if lastState.TreeSize != mockBackend.treeSize {
			t.Errorf("Expected tree size %d, got %d", mockBackend.treeSize, lastState.TreeSize)
		}
		if lastState.TreeHash != mockBackend.treeHash {
			t.Errorf("Expected tree hash %s, got %s", mockBackend.treeHash, lastState.TreeHash)
		}
	}

	// Verify cosignature was submitted
	if len(mockBackend.cosignatures) == 0 {
		t.Errorf("Expected cosignature to be submitted, but none found")
	}
}

// TestWitnessWatcherInvalidMAC tests that invalid MACs are rejected
func TestWitnessWatcherInvalidMAC(t *testing.T) {
	tempDir := t.TempDir()
	watchDir := filepath.Join(tempDir, "watch")
	witnessDir := filepath.Join(tempDir, "witness")
	
	if err := os.MkdirAll(watchDir, 0755); err != nil {
		t.Fatalf("Failed to create watch directory: %v", err)
	}

	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	keyFile := filepath.Join(tempDir, "key.json")
	keyContent := `{"logs": {"key": "` + testKey + `"}}`
	if err := os.WriteFile(keyFile, []byte(keyContent), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	witnessManager, err := NewWitnessManager(witnessDir, "test-witness")
	if err != nil {
		t.Fatalf("Failed to create witness manager: %v", err)
	}

	if err := witnessManager.InitCertificate(); err != nil {
		t.Fatalf("Failed to initialize witness certificate: %v", err)
	}

	mockBackend := &MockLogBackend{
		treeSize: 10,
		treeHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	watcher, err := NewWitnessWatcher(WitnessWatcherConfig{
		WatchDir:       watchDir,
		KeyFile:        keyFile,
		WitnessManager: witnessManager,
		LogBackend:     mockBackend,
	})
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	if err := watcher.Start(); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer watcher.Stop()

	// Create entry with invalid MAC
	entry := `{ "timestamp": "2024-06-24T07:41:59.049+0200", "seqno": 1, "ip": "172.21.0.69", "severity": "harmless", "message": { "code": 303, "text": "Test entry" }, "mac": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }`

	logFile := filepath.Join(watchDir, "invalid.log")
	if err := os.WriteFile(logFile, []byte(entry), 0644); err != nil {
		t.Fatalf("Failed to write log file: %v", err)
	}

	// Wait for processing
	time.Sleep(2 * time.Second)

	// Verify that no cosignature was submitted (validation failed)
	if len(mockBackend.cosignatures) > 0 {
		t.Errorf("Expected no cosignature for invalid MAC, but got %d", len(mockBackend.cosignatures))
	}
}

// TestWitnessWatcherConsistencyCheck tests fork detection
func TestWitnessWatcherConsistencyCheck(t *testing.T) {
	tempDir := t.TempDir()
	watchDir := filepath.Join(tempDir, "watch")
	witnessDir := filepath.Join(tempDir, "witness")
	
	if err := os.MkdirAll(watchDir, 0755); err != nil {
		t.Fatalf("Failed to create watch directory: %v", err)
	}

	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	keyFile := filepath.Join(tempDir, "key.json")
	keyContent := `{"logs": {"key": "` + testKey + `"}}`
	if err := os.WriteFile(keyFile, []byte(keyContent), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	witnessManager, err := NewWitnessManager(witnessDir, "test-witness")
	if err != nil {
		t.Fatalf("Failed to create witness manager: %v", err)
	}

	if err := witnessManager.InitCertificate(); err != nil {
		t.Fatalf("Failed to initialize witness certificate: %v", err)
	}

	mockBackend := &MockLogBackend{
		treeSize: 10,
		treeHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	watcher, err := NewWitnessWatcher(WitnessWatcherConfig{
		WatchDir:       watchDir,
		KeyFile:        keyFile,
		WitnessManager: witnessManager,
		LogBackend:     mockBackend,
	})
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	// Create initial witnessed state
	_, err = witnessManager.ObserveRemoteTree(10, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("Failed to create initial witnessed state: %v", err)
	}

	// Simulate tree shrinking (fork attack)
	mockBackend.treeSize = 5
	mockBackend.treeHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	// Test consistency check - should detect fork
	entry := `{ "timestamp": "2024-06-24T07:41:59.049+0200", "seqno": 1, "ip": "172.21.0.69", "severity": "harmless", "message": { "code": 303, "text": "Test entry" }, "mac": "0000000000000000000000000000000000000000000000000000000000000000" }`
	mac := computeValidMAC(entry, testKey)
	entry = strings.Replace(entry, "0000000000000000000000000000000000000000000000000000000000000000", mac, 1)

	logFile := filepath.Join(tempDir, "fork-test.log")
	if err := os.WriteFile(logFile, []byte(entry), 0644); err != nil {
		t.Fatalf("Failed to write log file: %v", err)
	}

	// Validate and check consistency - should fail
	err = watcher.ValidateAndCheckConsistency(logFile)
	if err == nil {
		t.Errorf("Expected fork detection error, got nil")
	} else if !strings.Contains(err.Error(), "FORK DETECTED") {
		t.Errorf("Expected 'FORK DETECTED' error, got: %v", err)
	}
}

// MockLogBackend implements StorageBackend for testing
type MockLogBackend struct {
	treeSize     int64
	treeHash     string
	cosignatures []WitnessCosignature
}

func (m *MockLogBackend) AddDraw(draw LotteryDraw) error {
	return nil
}

func (m *MockLogBackend) GetTreeSize() (int64, error) {
	return m.treeSize, nil
}

func (m *MockLogBackend) GetTreeHash(size int64) (string, error) {
	return m.treeHash, nil
}

func (m *MockLogBackend) GetDraw(index int64) (*LotteryDraw, error) {
	return nil, nil
}

func (m *MockLogBackend) AddWitnessCosignature(cosig WitnessCosignature) error {
	m.cosignatures = append(m.cosignatures, cosig)
	return nil
}

func (m *MockLogBackend) GetLatestWitnessCosignatures() ([]WitnessCosignature, error) {
	return m.cosignatures, nil
}

func (m *MockLogBackend) GetWitnessCosignatures(treeSize int64) ([]WitnessCosignature, error) {
	var result []WitnessCosignature
	for _, cosig := range m.cosignatures {
		if cosig.TreeSize == treeSize {
			result = append(result, cosig)
		}
	}
	return result, nil
}

func (m *MockLogBackend) ListDraws(startIndex, endIndex int64) ([]*LotteryDraw, error) {
	return nil, nil
}

func (m *MockLogBackend) VerifyIntegrity() error {
	return nil
}

// Helper function to compute valid MAC
func computeValidMAC(entry string, key string) string {
	const zeroMAC = "0000000000000000000000000000000000000000000000000000000000000000"
	
	keyBytes, _ := hex.DecodeString(key)
	h := hmac.New(sha256.New, keyBytes)
	h.Write([]byte(entry))
	return hex.EncodeToString(h.Sum(nil))
}
