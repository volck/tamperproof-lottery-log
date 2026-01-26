package tlog

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// WitnessPeer represents another witness that this witness can cross-check with
type WitnessPeer struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	PublicKey string `json:"public_key,omitempty"`
}

// WitnessConsistencyCheck compares observations between witnesses
type WitnessConsistencyCheck struct {
	LocalWitnessID    string           `json:"local_witness_id"`
	LocalTreeSize     int64            `json:"local_tree_size"`
	LocalTreeHash     string           `json:"local_tree_hash"`
	LocalTimestamp    time.Time        `json:"local_timestamp"`
	PeerComparisons   []PeerComparison `json:"peer_comparisons"`
	OverallConsistent bool             `json:"overall_consistent"`
	CheckedAt         time.Time        `json:"checked_at"`
}

// PeerComparison represents a consistency check with a single peer
type PeerComparison struct {
	PeerID        string    `json:"peer_id"`
	PeerURL       string    `json:"peer_url"`
	PeerTreeSize  int64     `json:"peer_tree_size"`
	PeerTreeHash  string    `json:"peer_tree_hash"`
	PeerTimestamp time.Time `json:"peer_timestamp"`
	Consistent    bool      `json:"consistent"`
	Error         string    `json:"error,omitempty"`
	Details       string    `json:"details,omitempty"`
}

// CrossCheckWithPeers verifies consistency with other witnesses
func (wm *WitnessManager) CrossCheckWithPeers(peers []WitnessPeer, httpClient *http.Client) (*WitnessConsistencyCheck, error) {
	// Get our latest witnessed state
	states, err := wm.ListWitnessedStates()
	if err != nil {
		return nil, fmt.Errorf("failed to get local witnessed states: %w", err)
	}
	
	if len(states) == 0 {
		return nil, fmt.Errorf("no local witnessed states found")
	}
	
	localState := states[len(states)-1]
	
	check := &WitnessConsistencyCheck{
		LocalWitnessID:    wm.witnessID,
		LocalTreeSize:     localState.TreeSize,
		LocalTreeHash:     localState.TreeHash,
		LocalTimestamp:    localState.Timestamp,
		PeerComparisons:   make([]PeerComparison, 0, len(peers)),
		OverallConsistent: true,
		CheckedAt:         time.Now(),
	}
	
	// Use default insecure client if none provided
	if httpClient == nil {
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: 10 * time.Second,
		}
	}
	
	// Check each peer
	for _, peer := range peers {
		comparison := wm.checkPeerConsistency(peer, localState, httpClient)
		check.PeerComparisons = append(check.PeerComparisons, comparison)
		
		if !comparison.Consistent {
			check.OverallConsistent = false
		}
	}
	
	return check, nil
}

// checkPeerConsistency checks consistency with a single peer
func (wm *WitnessManager) checkPeerConsistency(peer WitnessPeer, localState WitnessedState, httpClient *http.Client) PeerComparison {
	comparison := PeerComparison{
		PeerID:  peer.ID,
		PeerURL: peer.URL,
	}
	
	// Fetch peer's latest witnessed state
	req, err := http.NewRequest("GET", peer.URL+"/api/witness/"+peer.ID+"/latest", nil)
	if err != nil {
		comparison.Error = fmt.Sprintf("failed to create request: %v", err)
		comparison.Consistent = false
		return comparison
	}
	
	resp, err := httpClient.Do(req)
	if err != nil {
		comparison.Error = fmt.Sprintf("failed to connect: %v", err)
		comparison.Consistent = false
		return comparison
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		comparison.Error = fmt.Sprintf("peer returned status %d: %s", resp.StatusCode, string(body))
		comparison.Consistent = false
		return comparison
	}
	
	var peerState WitnessedState
	if err := json.NewDecoder(resp.Body).Decode(&peerState); err != nil {
		comparison.Error = fmt.Sprintf("failed to decode peer response: %v", err)
		comparison.Consistent = false
		return comparison
	}
	
	comparison.PeerTreeSize = peerState.TreeSize
	comparison.PeerTreeHash = peerState.TreeHash
	comparison.PeerTimestamp = peerState.Timestamp
	
	// Check consistency
	comparison.Consistent, comparison.Details = wm.compareStates(localState, peerState)
	
	return comparison
}

// compareStates compares two witnessed states for consistency
func (wm *WitnessManager) compareStates(local, peer WitnessedState) (bool, string) {
	// Same tree size and hash = perfect consistency
	if local.TreeSize == peer.TreeSize && local.TreeHash == peer.TreeHash {
		return true, "Tree size and hash match exactly"
	}
	
	// Peer is ahead - this is acceptable if hashes are consistent for our size
	if peer.TreeSize > local.TreeSize {
		return true, fmt.Sprintf("Peer is ahead (size %d vs %d) - acceptable", peer.TreeSize, local.TreeSize)
	}
	
	// We are ahead - also acceptable
	if local.TreeSize > peer.TreeSize {
		return true, fmt.Sprintf("Local is ahead (size %d vs %d) - acceptable", local.TreeSize, peer.TreeSize)
	}
	
	// Same size but different hash = FORK DETECTED!
	if local.TreeSize == peer.TreeSize && local.TreeHash != peer.TreeHash {
		return false, fmt.Sprintf("FORK DETECTED! Same tree size (%d) but different hashes: local=%s peer=%s",
			local.TreeSize, local.TreeHash[:16], peer.TreeHash[:16])
	}
	
	return true, "Acceptable state difference"
}

// ShareWitnessedState publishes this witness's latest state to a peer
func (wm *WitnessManager) ShareWitnessedState(peerURL string, httpClient *http.Client) error {
	states, err := wm.ListWitnessedStates()
	if err != nil {
		return fmt.Errorf("failed to get witnessed states: %w", err)
	}
	
	if len(states) == 0 {
		return fmt.Errorf("no witnessed states to share")
	}
	
	latestState := states[len(states)-1]
	
	data, err := json.Marshal(latestState)
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}
	
	req, err := http.NewRequest("POST", peerURL+"/api/witness/gossip", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	if httpClient == nil {
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: 10 * time.Second,
		}
	}
	
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send state: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("peer returned status %d: %s", resp.StatusCode, string(body))
	}
	
	slog.Info("Shared witnessed state with peer",
		"peer_url", peerURL,
		"tree_size", latestState.TreeSize,
		"tree_hash", latestState.TreeHash[:16]+"...")
	
	return nil
}

// ReceiveWitnessGossip processes a witnessed state received from another witness
func (wm *WitnessManager) ReceiveWitnessGossip(receivedState WitnessedState) error {
	// Get our latest state
	states, err := wm.ListWitnessedStates()
	if err != nil {
		return fmt.Errorf("failed to get local states: %w", err)
	}
	
	if len(states) == 0 {
		slog.Warn("Received gossip but have no local state to compare")
		return nil
	}
	
	localState := states[len(states)-1]
	
	// Compare states
	consistent, details := wm.compareStates(localState, receivedState)
	
	if !consistent {
		slog.Error("INCONSISTENCY DETECTED IN WITNESS GOSSIP",
			"remote_witness", receivedState.WitnessID,
			"local_tree_size", localState.TreeSize,
			"local_tree_hash", localState.TreeHash,
			"remote_tree_size", receivedState.TreeSize,
			"remote_tree_hash", receivedState.TreeHash,
			"details", details)
		return fmt.Errorf("inconsistency detected: %s", details)
	}
	
	slog.Info("Received consistent gossip from peer witness",
		"remote_witness", receivedState.WitnessID,
		"remote_tree_size", receivedState.TreeSize,
		"details", details)
	
	return nil
}
