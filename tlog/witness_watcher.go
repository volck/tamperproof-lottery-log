package tlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WitnessWatcher watches a folder for log file updates and validates them
type WitnessWatcher struct {
	witnessManager *WitnessManager
	watchDir       string
	keyFile        string
	logKey         string
	logger         *slog.Logger
	watcher        *fsnotify.Watcher
	serverURL      string // URL to query server for tree state
	stopChan       chan struct{}
	logBackend     StorageBackend // To query server state
}

// WitnessWatcherConfig holds configuration for the witness watcher
type WitnessWatcherConfig struct {
	WatchDir       string
	KeyFile        string
	WitnessManager *WitnessManager
	ServerURL      string
	Logger         *slog.Logger
	LogBackend     StorageBackend // Optional: for direct server access
}

// NewWitnessWatcher creates a new witness file watcher
func NewWitnessWatcher(config WitnessWatcherConfig) (*WitnessWatcher, error) {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	// Read the key file
	keyData, err := os.ReadFile(config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	var keyConfig struct {
		Logs struct {
			Key string `json:"key"`
		} `json:"logs"`
	}

	if err := json.Unmarshal(keyData, &keyConfig); err != nil {
		return nil, fmt.Errorf("failed to parse key file JSON: %w", err)
	}

	logKey := keyConfig.Logs.Key
	if logKey == "" {
		return nil, fmt.Errorf("log key not found in key file")
	}

	// Create fsnotify watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	// Create watch directory if it doesn't exist
	if err := os.MkdirAll(config.WatchDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create watch directory: %w", err)
	}

	return &WitnessWatcher{
		witnessManager: config.WitnessManager,
		watchDir:       config.WatchDir,
		keyFile:        config.KeyFile,
		logKey:         logKey,
		logger:         config.Logger,
		watcher:        watcher,
		serverURL:      config.ServerURL,
		stopChan:       make(chan struct{}),
		logBackend:     config.LogBackend,
	}, nil
}

// Start begins watching the directory for file changes
func (ww *WitnessWatcher) Start() error {
	// Add the watch directory
	if err := ww.watcher.Add(ww.watchDir); err != nil {
		return fmt.Errorf("failed to watch directory %s: %w", ww.watchDir, err)
	}

	ww.logger.Info("Witness watcher started", "watch_dir", ww.watchDir, "witness_id", ww.witnessManager.witnessID)

	// Start event processing loop
	go ww.processEvents()

	return nil
}

// Stop stops the watcher
func (ww *WitnessWatcher) Stop() error {
	close(ww.stopChan)
	return ww.watcher.Close()
}

// processEvents handles file system events
func (ww *WitnessWatcher) processEvents() {
	// Track last validation time to debounce rapid changes
	lastValidation := make(map[string]time.Time)
	debounceInterval := 1 * time.Second

	for {
		select {
		case event, ok := <-ww.watcher.Events:
			if !ok {
				return
			}

			// Only process write and create events
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				// Debounce - only validate if enough time has passed
				if lastTime, exists := lastValidation[event.Name]; exists {
					if time.Since(lastTime) < debounceInterval {
						continue
					}
				}
				lastValidation[event.Name] = time.Now()

				// Only process log files
				if !strings.HasSuffix(event.Name, ".log") && !strings.HasSuffix(event.Name, ".logs") {
					continue
				}

				ww.logger.Info("Detected file change", "file", event.Name, "operation", event.Op)

				// Process the file asynchronously to avoid blocking
				go ww.validateAndAck(event.Name)
			}

		case err, ok := <-ww.watcher.Errors:
			if !ok {
				return
			}
			ww.logger.Error("File watcher error", "error", err)

		case <-ww.stopChan:
			return
		}
	}
}

// validateAndAck validates a log file and acknowledges it if valid
func (ww *WitnessWatcher) validateAndAck(filePath string) {
	ww.logger.Info("Starting validation", "file", filePath)

	// Step 1: Validate HMAC for all entries in the file
	validatedLines, err := ww.validateLogFile(filePath)
	if err != nil {
		ww.logger.Error("HMAC validation failed", "file", filePath, "error", err)
		return
	}

	ww.logger.Info("HMAC validation passed", "file", filePath, "lines", validatedLines)

	// Step 2: Parse log entries and determine latest state
	latestSeqNo, latestTimestamp, err := ww.parseLogMetadata(filePath)
	if err != nil {
		ww.logger.Error("Failed to parse log metadata", "file", filePath, "error", err)
		return
	}

	ww.logger.Info("Log metadata", "file", filePath, "latest_seqno", latestSeqNo, "latest_timestamp", latestTimestamp)

	// Step 3: Query server for current tree state
	serverTreeSize, serverTreeHash, err := ww.queryServerState()
	if err != nil {
		ww.logger.Error("Failed to query server state", "error", err)
		return
	}

	ww.logger.Info("Server state", "tree_size", serverTreeSize, "tree_hash", serverTreeHash)

	// Step 4: Compare local validated data with server state
	// In a full implementation, we would verify inclusion proofs here
	// For now, we trust that if HMAC validates, we can observe the tree

	// Step 5: Create witnessed state and sign it
	witnessedState, err := ww.witnessManager.ObserveRemoteTree(serverTreeSize, serverTreeHash)
	if err != nil {
		ww.logger.Error("Failed to observe and sign tree", "error", err)
		return
	}

	ww.logger.Info("Tree state witnessed and signed",
		"tree_size", witnessedState.TreeSize,
		"tree_hash", witnessedState.TreeHash,
		"witness_id", witnessedState.WitnessID,
		"timestamp", witnessedState.Timestamp,
	)

	// Step 6: Submit cosignature to server (if configured)
	if ww.logBackend != nil {
		cosig := WitnessCosignature{
			WitnessID: witnessedState.WitnessID,
			TreeSize:  witnessedState.TreeSize,
			TreeHash:  witnessedState.TreeHash,
			Timestamp: witnessedState.Timestamp,
			Signature: witnessedState.Signature,
		}

		if err := ww.logBackend.AddWitnessCosignature(cosig); err != nil {
			ww.logger.Error("Failed to submit cosignature to server", "error", err)
			return
		}

		ww.logger.Info("Cosignature submitted to server", "witness_id", witnessedState.WitnessID)
	}

	ww.logger.Info("File validation and acknowledgment complete", "file", filePath)
}

// validateLogFile validates all entries in a log file
func (ww *WitnessWatcher) validateLogFile(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Increase buffer size for large lines
	const maxCapacity = 10 * 1024 * 1024 // 10MB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	lineNum := 0
	errors := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if line == "" {
			continue
		}

		// Validate MAC for this entry
		if err := ValidateLogEntryMAC(line, ww.logKey); err != nil {
			ww.logger.Error("MAC validation failed for line",
				"line", lineNum,
				"error", err,
			)
			errors++
		}
	}

	if err := scanner.Err(); err != nil {
		return lineNum, fmt.Errorf("error reading file: %w", err)
	}

	if errors > 0 {
		return lineNum, fmt.Errorf("FAILED: %d error(s) out of %d lines", errors, lineNum)
	}

	return lineNum, nil
}

// parseLogMetadata extracts metadata from log entries (latest seqno, timestamp)
func (ww *WitnessWatcher) parseLogMetadata(filePath string) (int, time.Time, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	const maxCapacity = 10 * 1024 * 1024
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	var latestSeqNo int
	var latestTimestamp time.Time

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var entry LotteryDraw
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// Skip invalid entries
			continue
		}

		if entry.SeqNo > latestSeqNo {
			latestSeqNo = entry.SeqNo
		}

		if entry.Timestamp.After(latestTimestamp) {
			latestTimestamp = entry.Timestamp
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, time.Time{}, fmt.Errorf("error reading file: %w", err)
	}

	return latestSeqNo, latestTimestamp, nil
}

// queryServerState queries the server for current tree state
func (ww *WitnessWatcher) queryServerState() (int64, string, error) {
	// If we have direct backend access, use it
	if ww.logBackend != nil {
		treeSize, err := ww.logBackend.GetTreeSize()
		if err != nil {
			return 0, "", fmt.Errorf("failed to get tree size from backend: %w", err)
		}

		if treeSize == 0 {
			return 0, "", fmt.Errorf("tree is empty")
		}

		treeHash, err := ww.logBackend.GetTreeHash(treeSize)
		if err != nil {
			return 0, "", fmt.Errorf("failed to get tree hash from backend: %w", err)
		}

		return treeSize, treeHash, nil
	}

	// Otherwise, would need to query via HTTP API
	// For now, return error if no backend is configured
	return 0, "", fmt.Errorf("no backend configured and HTTP API not yet implemented")
}

// ValidateAndCheckConsistency validates a new log file and checks consistency with previous state
func (ww *WitnessWatcher) ValidateAndCheckConsistency(filePath string) error {
	// Get previous witnessed state
	states, err := ww.witnessManager.ListWitnessedStates()
	if err != nil {
		return fmt.Errorf("failed to get previous states: %w", err)
	}

	var previousState *WitnessedState
	if len(states) > 0 {
		previousState = &states[len(states)-1]
	}

	// Validate the file
	if _, err := ww.validateLogFile(filePath); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Get current server state
	currentTreeSize, currentTreeHash, err := ww.queryServerState()
	if err != nil {
		return fmt.Errorf("failed to query server state: %w", err)
	}

	// If we have a previous state, verify consistency
	if previousState != nil {
		newState := WitnessedState{
			TreeSize: currentTreeSize,
			TreeHash: currentTreeHash,
		}

		// Check if tree grew (consistency requirement)
		if newState.TreeSize < previousState.TreeSize {
			return fmt.Errorf("tree size decreased: %d -> %d (FORK DETECTED)", previousState.TreeSize, newState.TreeSize)
		}

		if newState.TreeSize == previousState.TreeSize {
			// Tree size same, hash must be identical
			if newState.TreeHash != previousState.TreeHash {
				return fmt.Errorf("tree hash changed without size change (FORK DETECTED)")
			}
		}

		ww.logger.Info("Consistency check passed",
			"previous_size", previousState.TreeSize,
			"current_size", newState.TreeSize,
		)
	}

	return nil
}
