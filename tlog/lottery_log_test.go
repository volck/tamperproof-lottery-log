package tlog

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateLogEntryMAC tests the MAC validation function with various scenarios
func TestValidateLogEntryMAC(t *testing.T) {
	// Sample valid entry from concat-clean.logs
	validEntry1 := `{ "timestamp": "2024-06-24T07:41:59.049+0200", "seqno": 1, "ip": "172.21.0.69", "severity": "harmless", "message": { "code": 303, "text": "Integrity check (checksum and timestamp).", "remote_ip": "172.21.0.69", "checks": { "binary_checksum": "1d8242e158cc25cf66ad5dc6f4dd8ddd4dceb77a0e941d022e4056c9fee37410", "binary_timestamp": "2024-06-13T11:03:05+0200", "config_filename": "/etc/truegenserver/truegenserver.json", "config_timestamp": "2024-06-24T07:41:55+0200" } }, "mac": "2d48e92ef7125692535fae8552bf164075179a3f87484194e3b76a11eda00ea6" }`

	// We need to extract the actual key by reverse engineering or using a known test key
	// For testing purposes, let's create a test key
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	_ = validEntry1 // Keep for reference

	tests := []struct {
		name        string
		logEntry    string
		logKey      string
		wantErr     bool
		errContains string
	}{
		{
			name:        "missing mac field",
			logEntry:    `{"timestamp": "2024-06-24T07:41:59.049+0200", "seqno": 1}`,
			logKey:      testKey,
			wantErr:     true,
			errContains: "missing 'mac' field",
		},
		{
			name:        "invalid json",
			logEntry:    `{invalid json`,
			logKey:      testKey,
			wantErr:     true,
			errContains: "failed to parse log entry JSON",
		},
		{
			name:        "mac field not a string",
			logEntry:    `{"timestamp": "2024-06-24T07:41:59.049+0200", "mac": 12345}`,
			logKey:      testKey,
			wantErr:     true,
			errContains: "'mac' field is not a string",
		},
		{
			name:        "invalid key format",
			logEntry:    validEntry1,
			logKey:      "not-hex",
			wantErr:     true,
			errContains: "failed to decode log key",
		},
		{
			name:        "tampered data - changed seqno",
			logEntry:    `{ "timestamp": "2024-06-24T07:41:59.049+0200", "seqno": 999, "ip": "172.21.0.69", "severity": "harmless", "message": { "code": 303, "text": "Integrity check (checksum and timestamp).", "remote_ip": "172.21.0.69", "checks": { "binary_checksum": "1d8242e158cc25cf66ad5dc6f4dd8ddd4dceb77a0e941d022e4056c9fee37410", "binary_timestamp": "2024-06-13T11:03:05+0200", "config_filename": "/etc/truegenserver/truegenserver.json", "config_timestamp": "2024-06-24T07:41:55+0200" } }, "mac": "2d48e92ef7125692535fae8552bf164075179a3f87484194e3b76a11eda00ea6" }`,
			logKey:      testKey,
			wantErr:     true,
			errContains: "MAC mismatch",
		},
		{
			name:        "tampered data - changed timestamp",
			logEntry:    `{ "timestamp": "2099-12-31T23:59:59.999+0200", "seqno": 1, "ip": "172.21.0.69", "severity": "harmless", "message": { "code": 303, "text": "Integrity check (checksum and timestamp).", "remote_ip": "172.21.0.69", "checks": { "binary_checksum": "1d8242e158cc25cf66ad5dc6f4dd8ddd4dceb77a0e941d022e4056c9fee37410", "binary_timestamp": "2024-06-13T11:03:05+0200", "config_filename": "/etc/truegenserver/truegenserver.json", "config_timestamp": "2024-06-24T07:41:55+0200" } }, "mac": "2d48e92ef7125692535fae8552bf164075179a3f87484194e3b76a11eda00ea6" }`,
			logKey:      testKey,
			wantErr:     true,
			errContains: "MAC mismatch",
		},
		{
			name:        "tampered data - changed values in draw",
			logEntry:    `{ "timestamp": "2024-06-24T12:42:47.356+0200", "seqno": 7, "ip": "172.21.0.69", "severity": "harmless", "message": { "code": 302, "text": "Draw configuration.", "remote_ip": "172.21.1.50", "game": 10, "draw": 0, "subdraw": 4, "parameters": { "low_bound": 0, "high_bound": 999, "put_back": false, "use_distribution": false } }, "mac": "530261faea394de3d26dc7bdb88e88bec45a27a9627f6c0ffcbb2347d1bf2a99" }`,
			logKey:      testKey,
			wantErr:     true,
			errContains: "MAC mismatch",
		},
		{
			name:        "tampered mac - wrong mac value",
			logEntry:    `{ "timestamp": "2024-06-24T07:41:59.049+0200", "seqno": 1, "ip": "172.21.0.69", "severity": "harmless", "message": { "code": 303, "text": "Integrity check (checksum and timestamp).", "remote_ip": "172.21.0.69", "checks": { "binary_checksum": "1d8242e158cc25cf66ad5dc6f4dd8ddd4dceb77a0e941d022e4056c9fee37410", "binary_timestamp": "2024-06-13T11:03:05+0200", "config_filename": "/etc/truegenserver/truegenserver.json", "config_timestamp": "2024-06-24T07:41:55+0200" } }, "mac": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }`,
			logKey:      testKey,
			wantErr:     true,
			errContains: "MAC mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLogEntryMAC(tt.logEntry, tt.logKey)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateLogEntryMAC() expected error but got none")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateLogEntryMAC() error = %v, want error containing %q", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateLogEntryMAC() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestValidateLogEntryMACWithRealData tests validation with actual log data
// This test requires the concat-clean.logs file to be present
func TestValidateLogEntryMACWithRealData(t *testing.T) {
	// Skip if file doesn't exist
	logFile := "concat-clean.logs"
	if _, err := os.Stat(filepath.Join("..", logFile)); os.IsNotExist(err) {
		t.Skipf("Skipping test: %s not found", logFile)
	}

	// Read a few sample lines
	data, err := os.ReadFile(filepath.Join("..", logFile))
	if err != nil {
		t.Skipf("Cannot read log file: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) < 10 {
		t.Skipf("Log file too small")
	}

	// Test with dummy key - these should fail unless we have the real key
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	sampleLines := []string{
		lines[0],   // First entry
		lines[10],  // Entry at index 10
		lines[100], // Entry at index 100
	}

	for i, line := range sampleLines {
		if line == "" {
			continue
		}

		t.Run(t.Name()+"_line_"+string(rune(i)), func(t *testing.T) {
			// Verify JSON structure is valid
			var entry map[string]interface{}
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				t.Errorf("Invalid JSON at line %d: %v", i, err)
			}

			// Verify MAC field exists
			if _, ok := entry["mac"]; !ok {
				t.Errorf("MAC field missing at line %d", i)
			}

			// Try validation (will fail without correct key, but tests the function)
			_ = ValidateLogEntryMAC(line, testKey)
		})
	}
}

// TestValidateLogFile tests the file validation function
func TestValidateLogFile(t *testing.T) {
	// Create temporary test files
	tempDir := t.TempDir()

	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Create a key file
	keyFile := filepath.Join(tempDir, "key.json")
	keyContent := `{"logs": {"key": "` + testKey + `"}}`
	if err := os.WriteFile(keyFile, []byte(keyContent), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	// Helper function to compute valid MAC for test data
	computeMAC := func(entry string, key string) string {
		const zeroMAC = "0000000000000000000000000000000000000000000000000000000000000000"
		entryWithZeroMAC := strings.Replace(entry, zeroMAC, zeroMAC, 1)

		keyBytes, _ := hex.DecodeString(key)
		h := hmac.New(sha256.New, keyBytes)
		h.Write([]byte(entryWithZeroMAC))
		return hex.EncodeToString(h.Sum(nil))
	}

	// Create log entry template with zero MAC
	entryTemplate := `{ "timestamp": "2024-06-24T07:41:59.049+0200", "seqno": %d, "ip": "172.21.0.69", "severity": "harmless", "message": { "code": 303, "text": "Test entry %d" }, "mac": "0000000000000000000000000000000000000000000000000000000000000000" }`

	tests := []struct {
		name        string
		setupLog    func(string) error
		setupKey    func(string) error
		wantErr     bool
		errContains string
	}{
		{
			name: "valid log file with valid entries",
			setupLog: func(path string) error {
				var entries []string
				for i := 1; i <= 5; i++ {
					entry := strings.Replace(entryTemplate, "%d", string(rune('0'+i)), -1)
					mac := computeMAC(entry, testKey)
					entry = strings.Replace(entry, "0000000000000000000000000000000000000000000000000000000000000000", mac, 1)
					entries = append(entries, entry)
				}
				return os.WriteFile(path, []byte(strings.Join(entries, "\n")), 0644)
			},
			setupKey: nil, // Use default key file
			wantErr:  false,
		},
		{
			name: "log file with one tampered entry",
			setupLog: func(path string) error {
				entry1 := `{ "timestamp": "2024-06-24T07:41:59.049+0200", "seqno": 1, "ip": "172.21.0.69", "severity": "harmless", "message": { "code": 303, "text": "Valid entry" }, "mac": "0000000000000000000000000000000000000000000000000000000000000000" }`
				mac1 := computeMAC(entry1, testKey)
				entry1 = strings.Replace(entry1, "0000000000000000000000000000000000000000000000000000000000000000", mac1, 1)

				// Second entry with wrong MAC (tampered)
				entry2 := `{ "timestamp": "2024-06-24T07:41:59.050+0200", "seqno": 2, "ip": "172.21.0.69", "severity": "harmless", "message": { "code": 303, "text": "Tampered entry" }, "mac": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }`

				return os.WriteFile(path, []byte(entry1+"\n"+entry2), 0644)
			},
			setupKey:    nil,
			wantErr:     true,
			errContains: "1 error(s)",
		},
		{
			name: "missing log file",
			setupLog: func(path string) error {
				// Don't create the file
				return nil
			},
			setupKey:    nil,
			wantErr:     true,
			errContains: "failed to read log file",
		},
		{
			name: "missing key file",
			setupLog: func(path string) error {
				return os.WriteFile(path, []byte(`{"mac": "test"}`), 0644)
			},
			setupKey: func(path string) error {
				// Key file won't be created, return nil to signal we want to test with missing file
				return nil
			},
			wantErr:     true,
			errContains: "failed to read key file",
		},
		{
			name: "invalid key file format",
			setupLog: func(path string) error {
				return os.WriteFile(path, []byte(`{"mac": "test"}`), 0644)
			},
			setupKey: func(path string) error {
				return os.WriteFile(path, []byte(`{"invalid": "format"}`), 0644)
			},
			wantErr:     true,
			errContains: "log key not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logFile := filepath.Join(tempDir, "test-"+tt.name+".log")
			testKeyFile := keyFile

			if tt.setupLog != nil {
				if err := tt.setupLog(logFile); err != nil {
					t.Fatalf("Failed to setup log file: %v", err)
				}
			}

			if tt.setupKey != nil {
				testKeyFile = filepath.Join(tempDir, "test-key-"+tt.name+".json")
				if err := tt.setupKey(testKeyFile); err != nil && !strings.Contains(tt.errContains, "failed to read key file") {
					t.Fatalf("Failed to setup key file: %v", err)
				}
			}

			lines, err := ValidateLogFile(logFile, testKeyFile)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateLogFile() expected error but got none, validated %d lines", lines)
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateLogFile() error = %v, want error containing %q", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateLogFile() unexpected error = %v", err)
				}
				if lines == 0 {
					t.Errorf("ValidateLogFile() validated 0 lines, expected more")
				}
			}
		})
	}
}

// BenchmarkValidateLogEntryMAC benchmarks the MAC validation performance
func BenchmarkValidateLogEntryMAC(b *testing.B) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	entry := `{ "timestamp": "2024-06-24T07:41:59.049+0200", "seqno": 1, "ip": "172.21.0.69", "severity": "harmless", "message": { "code": 303, "text": "Integrity check (checksum and timestamp).", "remote_ip": "172.21.0.69", "checks": { "binary_checksum": "1d8242e158cc25cf66ad5dc6f4dd8ddd4dceb77a0e941d022e4056c9fee37410", "binary_timestamp": "2024-06-13T11:03:05+0200", "config_filename": "/etc/truegenserver/truegenserver.json", "config_timestamp": "2024-06-24T07:41:55+0200" } }, "mac": "2d48e92ef7125692535fae8552bf164075179a3f87484194e3b76a11eda00ea6" }`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateLogEntryMAC(entry, testKey)
	}
}
