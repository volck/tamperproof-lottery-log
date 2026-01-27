package tlog

import (
	"fmt"
	"time"
)

// QuorumConfig defines the quorum requirements for witness agreement
type QuorumConfig struct {
	// MinWitnesses is the minimum number of witnesses required
	MinWitnesses int
	
	// QuorumThreshold is the fraction of witnesses that must agree (0.0-1.0)
	// For example, 0.67 means 2/3 majority
	QuorumThreshold float64
	
	// MaxWaitTime is how long to wait for quorum before timing out
	MaxWaitTime time.Duration
	
	// KnownWitnesses is the list of all known witness IDs
	KnownWitnesses []string
}

// QuorumResult represents the result of a quorum check
type QuorumResult struct {
	TreeSize           int64                  `json:"tree_size"`
	TreeHash           string                 `json:"tree_hash"`
	QuorumAchieved     bool                   `json:"quorum_achieved"`
	RequiredSignatures int                    `json:"required_signatures"`
	ReceivedSignatures int                    `json:"received_signatures"`
	SigningWitnesses   []string               `json:"signing_witnesses"`
	MissingWitnesses   []string               `json:"missing_witnesses"`
	Timestamp          time.Time              `json:"timestamp"`
	Details            string                 `json:"details,omitempty"`
	Cosignatures       []WitnessCosignature   `json:"cosignatures"`
}

// CheckQuorum verifies if enough witnesses have signed a tree state
func CheckQuorum(cosignatures []WitnessCosignature, config QuorumConfig, treeSize int64, treeHash string) (*QuorumResult, error) {
	result := &QuorumResult{
		TreeSize:           treeSize,
		TreeHash:           treeHash,
		ReceivedSignatures: 0,
		SigningWitnesses:   make([]string, 0),
		MissingWitnesses:   make([]string, 0),
		Timestamp:          time.Now(),
		Cosignatures:       cosignatures,
	}

	// Calculate required signatures based on threshold
	totalWitnesses := len(config.KnownWitnesses)
	if totalWitnesses < config.MinWitnesses {
		return result, fmt.Errorf("insufficient known witnesses: have %d, need at least %d", totalWitnesses, config.MinWitnesses)
	}

	result.RequiredSignatures = int(float64(totalWitnesses) * config.QuorumThreshold)
	if result.RequiredSignatures < config.MinWitnesses {
		result.RequiredSignatures = config.MinWitnesses
	}

	// Track which witnesses have signed
	signedWitnesses := make(map[string]bool)
	for _, cosig := range cosignatures {
		// Verify signature is for the correct tree state
		if cosig.TreeSize == treeSize && cosig.TreeHash == treeHash {
			signedWitnesses[cosig.WitnessID] = true
			result.SigningWitnesses = append(result.SigningWitnesses, cosig.WitnessID)
		}
	}

	result.ReceivedSignatures = len(result.SigningWitnesses)

	// Identify missing witnesses
	for _, witnessID := range config.KnownWitnesses {
		if !signedWitnesses[witnessID] {
			result.MissingWitnesses = append(result.MissingWitnesses, witnessID)
		}
	}

	// Check if quorum is achieved
	if result.ReceivedSignatures >= result.RequiredSignatures {
		result.QuorumAchieved = true
		result.Details = fmt.Sprintf("Quorum achieved: %d/%d witnesses signed (threshold: %.0f%%)",
			result.ReceivedSignatures, totalWitnesses, config.QuorumThreshold*100)
	} else {
		result.QuorumAchieved = false
		result.Details = fmt.Sprintf("Quorum not achieved: %d/%d witnesses signed, need %d (threshold: %.0f%%)",
			result.ReceivedSignatures, totalWitnesses, result.RequiredSignatures, config.QuorumThreshold*100)
	}

	return result, nil
}

// WaitForQuorum polls for cosignatures until quorum is achieved or timeout
func WaitForQuorum(backend StorageBackend, config QuorumConfig, treeSize int64, treeHash string) (*QuorumResult, error) {
	startTime := time.Now()
	pollInterval := 1 * time.Second
	
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	timeout := time.After(config.MaxWaitTime)

	for {
		select {
		case <-timeout:
			// One final check before giving up
			cosignatures, _ := backend.GetWitnessCosignatures(treeSize)
			result, _ := CheckQuorum(cosignatures, config, treeSize, treeHash)
			result.Details = fmt.Sprintf("Timeout after %v: %s", config.MaxWaitTime, result.Details)
			return result, fmt.Errorf("quorum timeout: %s", result.Details)

		case <-ticker.C:
			// Check current cosignatures
			cosignatures, err := backend.GetWitnessCosignatures(treeSize)
			if err != nil {
				continue // Retry on error
			}

			result, err := CheckQuorum(cosignatures, config, treeSize, treeHash)
			if err != nil {
				return result, err
			}

			if result.QuorumAchieved {
				elapsed := time.Since(startTime)
				result.Details = fmt.Sprintf("Quorum achieved after %v: %s", elapsed.Round(time.Millisecond), result.Details)
				return result, nil
			}
		}
	}
}

// VerifyQuorumSignatures validates all signatures in a quorum result
func VerifyQuorumSignatures(result *QuorumResult, publicKeys map[string]string) error {
	verifiedCount := 0
	
	for _, cosig := range result.Cosignatures {
		if cosig.TreeSize != result.TreeSize || cosig.TreeHash != result.TreeHash {
			continue // Skip signatures for different states
		}

		pubKeyPEM, ok := publicKeys[cosig.WitnessID]
		if !ok {
			return fmt.Errorf("no public key found for witness %s", cosig.WitnessID)
		}

		pubKey, err := LoadPublicKeyFromPEM(pubKeyPEM)
		if err != nil {
			return fmt.Errorf("failed to load public key for witness %s: %w", cosig.WitnessID, err)
		}

		// Create a temporary witness manager to verify signature
		wm := &WitnessManager{
			witnessID: cosig.WitnessID,
			publicKey: pubKey,
		}

		witnessedState := WitnessedState{
			TreeSize:  cosig.TreeSize,
			TreeHash:  cosig.TreeHash,
			Timestamp: cosig.Timestamp,
			WitnessID: cosig.WitnessID,
			Signature: cosig.Signature,
		}

		if err := wm.VerifySignature(witnessedState); err != nil {
			return fmt.Errorf("signature verification failed for witness %s: %w", cosig.WitnessID, err)
		}

		verifiedCount++
	}

	if verifiedCount < result.RequiredSignatures {
		return fmt.Errorf("insufficient verified signatures: have %d, need %d", verifiedCount, result.RequiredSignatures)
	}

	return nil
}

// QuorumPolicy defines when to require quorum
type QuorumPolicy int

const (
	// QuorumNever never requires quorum (independent witness operation)
	QuorumNever QuorumPolicy = iota
	
	// QuorumForPublish requires quorum before publishing tree hash
	QuorumForPublish
	
	// QuorumForConfirmation requires quorum to confirm draws
	QuorumForConfirmation
	
	// QuorumStrict requires quorum for all operations
	QuorumStrict
)

// QuorumDecision determines if an operation should proceed based on quorum status
func QuorumDecision(policy QuorumPolicy, result *QuorumResult) (bool, string) {
	switch policy {
	case QuorumNever:
		return true, "Quorum not required by policy"
		
	case QuorumForPublish, QuorumForConfirmation, QuorumStrict:
		if result.QuorumAchieved {
			return true, fmt.Sprintf("Quorum achieved: %d/%d witnesses", result.ReceivedSignatures, len(result.SigningWitnesses)+len(result.MissingWitnesses))
		}
		return false, fmt.Sprintf("Quorum not achieved: %d/%d witnesses (need %d)", 
			result.ReceivedSignatures, 
			len(result.SigningWitnesses)+len(result.MissingWitnesses),
			result.RequiredSignatures)
	}
	
	return false, "Unknown quorum policy"
}
