package tlog

import (
	"testing"
	"time"
)

func TestCheckQuorum(t *testing.T) {
	tests := []struct {
		name             string
		cosignatures     []WitnessCosignature
		config           QuorumConfig
		treeSize         int64
		treeHash         string
		wantQuorum       bool
		wantSigning      int
		wantMissing      int
		wantRequiredSigs int
	}{
		{
			name: "2/3 quorum achieved",
			cosignatures: []WitnessCosignature{
				{WitnessID: "w1", TreeSize: 100, TreeHash: "abc123", Timestamp: time.Now()},
				{WitnessID: "w2", TreeSize: 100, TreeHash: "abc123", Timestamp: time.Now()},
			},
			config: QuorumConfig{
				MinWitnesses:    2,
				QuorumThreshold: 0.67,
				KnownWitnesses:  []string{"w1", "w2", "w3"},
			},
			treeSize:         100,
			treeHash:         "abc123",
			wantQuorum:       true,
			wantSigning:      2,
			wantMissing:      1,
			wantRequiredSigs: 2,
		},
		{
			name: "2/3 quorum not achieved - only 1 signature",
			cosignatures: []WitnessCosignature{
				{WitnessID: "w1", TreeSize: 100, TreeHash: "abc123", Timestamp: time.Now()},
			},
			config: QuorumConfig{
				MinWitnesses:    2,
				QuorumThreshold: 0.67,
				KnownWitnesses:  []string{"w1", "w2", "w3"},
			},
			treeSize:         100,
			treeHash:         "abc123",
			wantQuorum:       false,
			wantSigning:      1,
			wantMissing:      2,
			wantRequiredSigs: 2,
		},
		{
			name: "3/4 quorum achieved",
			cosignatures: []WitnessCosignature{
				{WitnessID: "w1", TreeSize: 100, TreeHash: "abc123", Timestamp: time.Now()},
				{WitnessID: "w2", TreeSize: 100, TreeHash: "abc123", Timestamp: time.Now()},
				{WitnessID: "w3", TreeSize: 100, TreeHash: "abc123", Timestamp: time.Now()},
			},
			config: QuorumConfig{
				MinWitnesses:    3,
				QuorumThreshold: 0.75,
				KnownWitnesses:  []string{"w1", "w2", "w3", "w4"},
			},
			treeSize:         100,
			treeHash:         "abc123",
			wantQuorum:       true,
			wantSigning:      3,
			wantMissing:      1,
			wantRequiredSigs: 3,
		},
		{
			name: "ignore signatures for wrong tree size",
			cosignatures: []WitnessCosignature{
				{WitnessID: "w1", TreeSize: 100, TreeHash: "abc123", Timestamp: time.Now()},
				{WitnessID: "w2", TreeSize: 99, TreeHash: "abc123", Timestamp: time.Now()},
				{WitnessID: "w3", TreeSize: 100, TreeHash: "different", Timestamp: time.Now()},
			},
			config: QuorumConfig{
				MinWitnesses:    2,
				QuorumThreshold: 0.67,
				KnownWitnesses:  []string{"w1", "w2", "w3"},
			},
			treeSize:         100,
			treeHash:         "abc123",
			wantQuorum:       false,
			wantSigning:      1,
			wantMissing:      2,
			wantRequiredSigs: 2,
		},
		{
			name: "unanimous agreement - 100% threshold",
			cosignatures: []WitnessCosignature{
				{WitnessID: "w1", TreeSize: 100, TreeHash: "abc123", Timestamp: time.Now()},
				{WitnessID: "w2", TreeSize: 100, TreeHash: "abc123", Timestamp: time.Now()},
				{WitnessID: "w3", TreeSize: 100, TreeHash: "abc123", Timestamp: time.Now()},
			},
			config: QuorumConfig{
				MinWitnesses:    3,
				QuorumThreshold: 1.0,
				KnownWitnesses:  []string{"w1", "w2", "w3"},
			},
			treeSize:         100,
			treeHash:         "abc123",
			wantQuorum:       true,
			wantSigning:      3,
			wantMissing:      0,
			wantRequiredSigs: 3,
		},
		{
			name: "simple majority - 51%",
			cosignatures: []WitnessCosignature{
				{WitnessID: "w1", TreeSize: 100, TreeHash: "abc123", Timestamp: time.Now()},
				{WitnessID: "w2", TreeSize: 100, TreeHash: "abc123", Timestamp: time.Now()},
				{WitnessID: "w3", TreeSize: 100, TreeHash: "abc123", Timestamp: time.Now()},
			},
			config: QuorumConfig{
				MinWitnesses:    3,
				QuorumThreshold: 0.51,
				KnownWitnesses:  []string{"w1", "w2", "w3", "w4", "w5"},
			},
			treeSize:         100,
			treeHash:         "abc123",
			wantQuorum:       true,
			wantSigning:      3,
			wantMissing:      2,
			wantRequiredSigs: 3, // 0.51 * 5 = 2.55 -> 3
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CheckQuorum(tt.cosignatures, tt.config, tt.treeSize, tt.treeHash)
			if err != nil {
				t.Fatalf("CheckQuorum() error = %v", err)
			}

			if result.QuorumAchieved != tt.wantQuorum {
				t.Errorf("QuorumAchieved = %v, want %v", result.QuorumAchieved, tt.wantQuorum)
			}

			if result.ReceivedSignatures != tt.wantSigning {
				t.Errorf("ReceivedSignatures = %d, want %d", result.ReceivedSignatures, tt.wantSigning)
			}

			if len(result.MissingWitnesses) != tt.wantMissing {
				t.Errorf("MissingWitnesses count = %d, want %d", len(result.MissingWitnesses), tt.wantMissing)
			}

			if result.RequiredSignatures != tt.wantRequiredSigs {
				t.Errorf("RequiredSignatures = %d, want %d", result.RequiredSignatures, tt.wantRequiredSigs)
			}

			if result.TreeSize != tt.treeSize {
				t.Errorf("TreeSize = %d, want %d", result.TreeSize, tt.treeSize)
			}

			if result.TreeHash != tt.treeHash {
				t.Errorf("TreeHash = %s, want %s", result.TreeHash, tt.treeHash)
			}
		})
	}
}

func TestCheckQuorumErrors(t *testing.T) {
	tests := []struct {
		name         string
		config       QuorumConfig
		wantErrorMsg string
	}{
		{
			name: "insufficient known witnesses",
			config: QuorumConfig{
				MinWitnesses:    3,
				QuorumThreshold: 0.67,
				KnownWitnesses:  []string{"w1", "w2"},
			},
			wantErrorMsg: "insufficient known witnesses",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CheckQuorum([]WitnessCosignature{}, tt.config, 100, "abc123")
			if err == nil {
				t.Errorf("Expected error containing %q, got nil", tt.wantErrorMsg)
			} else if err.Error() != tt.wantErrorMsg && len(tt.wantErrorMsg) > 0 {
				// Check if error contains expected message
				if len(err.Error()) > 0 && len(tt.wantErrorMsg) > 0 {
					// Simple contains check
					found := false
					for i := 0; i <= len(err.Error())-len(tt.wantErrorMsg); i++ {
						if err.Error()[i:i+len(tt.wantErrorMsg)] == tt.wantErrorMsg {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Error = %q, want error containing %q", err.Error(), tt.wantErrorMsg)
					}
				}
			}
		})
	}
}

func TestQuorumDecision(t *testing.T) {
	tests := []struct {
		name         string
		policy       QuorumPolicy
		result       *QuorumResult
		wantProceed  bool
		wantContains string
	}{
		{
			name:   "never policy always proceeds",
			policy: QuorumNever,
			result: &QuorumResult{
				QuorumAchieved: false,
			},
			wantProceed:  true,
			wantContains: "not required",
		},
		{
			name:   "publish policy with quorum",
			policy: QuorumForPublish,
			result: &QuorumResult{
				QuorumAchieved:     true,
				ReceivedSignatures: 3,
				SigningWitnesses:   []string{"w1", "w2", "w3"},
			},
			wantProceed:  true,
			wantContains: "achieved",
		},
		{
			name:   "publish policy without quorum",
			policy: QuorumForPublish,
			result: &QuorumResult{
				QuorumAchieved:     false,
				ReceivedSignatures: 1,
				RequiredSignatures: 2,
				SigningWitnesses:   []string{"w1"},
				MissingWitnesses:   []string{"w2", "w3"},
			},
			wantProceed:  false,
			wantContains: "not achieved",
		},
		{
			name:   "strict policy with quorum",
			policy: QuorumStrict,
			result: &QuorumResult{
				QuorumAchieved:     true,
				ReceivedSignatures: 3,
			},
			wantProceed:  true,
			wantContains: "achieved",
		},
		{
			name:   "strict policy without quorum",
			policy: QuorumStrict,
			result: &QuorumResult{
				QuorumAchieved:     false,
				ReceivedSignatures: 2,
				RequiredSignatures: 3,
			},
			wantProceed:  false,
			wantContains: "not achieved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proceed, details := QuorumDecision(tt.policy, tt.result)

			if proceed != tt.wantProceed {
				t.Errorf("QuorumDecision() proceed = %v, want %v", proceed, tt.wantProceed)
			}

			// Simple contains check
			found := false
			for i := 0; i <= len(details)-len(tt.wantContains); i++ {
				if details[i:i+len(tt.wantContains)] == tt.wantContains {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("QuorumDecision() details = %q, want to contain %q", details, tt.wantContains)
			}
		})
	}
}

func TestWaitForQuorum(t *testing.T) {
	// Create mock backend
	mockBackend := &MockLogBackend{
		treeSize:     100,
		treeHash:     "abc123",
		cosignatures: []WitnessCosignature{},
	}

	config := QuorumConfig{
		MinWitnesses:    2,
		QuorumThreshold: 0.67,
		KnownWitnesses:  []string{"w1", "w2", "w3"},
		MaxWaitTime:     2 * time.Second,
	}

	// Test timeout scenario
	t.Run("timeout without quorum", func(t *testing.T) {
		// Add only 1 signature (not enough for quorum)
		mockBackend.cosignatures = []WitnessCosignature{
			{WitnessID: "w1", TreeSize: 100, TreeHash: "abc123", Timestamp: time.Now()},
		}

		config.MaxWaitTime = 1 * time.Second
		start := time.Now()
		result, err := WaitForQuorum(mockBackend, config, 100, "abc123")
		elapsed := time.Since(start)

		if err == nil {
			t.Errorf("Expected timeout error, got nil")
		}

		if result.QuorumAchieved {
			t.Errorf("Expected quorum not achieved, got achieved")
		}

		if elapsed < 900*time.Millisecond {
			t.Errorf("Expected to wait ~1s, waited only %v", elapsed)
		}
	})

	// Test immediate quorum
	t.Run("immediate quorum", func(t *testing.T) {
		// Add enough signatures for quorum
		mockBackend.cosignatures = []WitnessCosignature{
			{WitnessID: "w1", TreeSize: 100, TreeHash: "abc123", Timestamp: time.Now()},
			{WitnessID: "w2", TreeSize: 100, TreeHash: "abc123", Timestamp: time.Now()},
		}

		config.MaxWaitTime = 5 * time.Second
		start := time.Now()
		result, err := WaitForQuorum(mockBackend, config, 100, "abc123")
		elapsed := time.Since(start)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		if !result.QuorumAchieved {
			t.Errorf("Expected quorum achieved, got not achieved")
		}

		if elapsed > 2*time.Second {
			t.Errorf("Expected quick return, but waited %v", elapsed)
		}
	})
}

func TestQuorumWithRealSignatures(t *testing.T) {
	// Create witness managers
	tempDir := t.TempDir()

	wm1, _ := NewWitnessManager(tempDir, "witness-1")
	wm1.InitCertificate()

	wm2, _ := NewWitnessManager(tempDir, "witness-2")
	wm2.InitCertificate()

	wm3, _ := NewWitnessManager(tempDir, "witness-3")
	wm3.InitCertificate()

	// Create witnessed states
	treeSize := int64(100)
	treeHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	state1, _ := wm1.ObserveRemoteTree(treeSize, treeHash)
	state2, _ := wm2.ObserveRemoteTree(treeSize, treeHash)
	state3, _ := wm3.ObserveRemoteTree(treeSize, treeHash)

	// Create cosignatures
	cosignatures := []WitnessCosignature{
		{
			WitnessID: state1.WitnessID,
			TreeSize:  state1.TreeSize,
			TreeHash:  state1.TreeHash,
			Timestamp: state1.Timestamp,
			Signature: state1.Signature,
		},
		{
			WitnessID: state2.WitnessID,
			TreeSize:  state2.TreeSize,
			TreeHash:  state2.TreeHash,
			Timestamp: state2.Timestamp,
			Signature: state2.Signature,
		},
		{
			WitnessID: state3.WitnessID,
			TreeSize:  state3.TreeSize,
			TreeHash:  state3.TreeHash,
			Timestamp: state3.Timestamp,
			Signature: state3.Signature,
		},
	}

	config := QuorumConfig{
		MinWitnesses:    2,
		QuorumThreshold: 0.67,
		KnownWitnesses:  []string{"witness-1", "witness-2", "witness-3"},
	}

	result, err := CheckQuorum(cosignatures, config, treeSize, treeHash)
	if err != nil {
		t.Fatalf("CheckQuorum() error = %v", err)
	}

	if !result.QuorumAchieved {
		t.Errorf("Expected quorum achieved with 3 signatures")
	}

	if result.ReceivedSignatures != 3 {
		t.Errorf("Expected 3 signatures, got %d", result.ReceivedSignatures)
	}

	// Verify signatures
	pubKeys := make(map[string]string)
	pubKey1, _ := wm1.ExportPublicKey()
	pubKey2, _ := wm2.ExportPublicKey()
	pubKey3, _ := wm3.ExportPublicKey()

	pubKeys["witness-1"] = pubKey1
	pubKeys["witness-2"] = pubKey2
	pubKeys["witness-3"] = pubKey3

	if err := VerifyQuorumSignatures(result, pubKeys); err != nil {
		t.Errorf("VerifyQuorumSignatures() error = %v", err)
	}
}
