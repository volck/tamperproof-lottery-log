package tlog

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/mod/sumdb/tlog"
)

// WitnessedState represents a tree state observed and signed by a witness
type WitnessedState struct {
	TreeSize  int64     `json:"tree_size"`
	TreeHash  string    `json:"tree_hash"`
	Timestamp time.Time `json:"timestamp"`
	WitnessID string    `json:"witness_id"`
	Signature string    `json:"signature"`
}

// WitnessManager handles witness operations
type WitnessManager struct {
	dataDir    string
	witnessDir string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	witnessID  string
}

// NewWitnessManager creates a new witness manager
func NewWitnessManager(dataDir string, witnessID string) (*WitnessManager, error) {
	witnessDir := filepath.Join(dataDir, "witnesses", witnessID)
	if err := os.MkdirAll(witnessDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create witness directory: %w", err)
	}

	return &WitnessManager{
		dataDir:    dataDir,
		witnessDir: witnessDir,
		witnessID:  witnessID,
	}, nil
}

// InitCertificate generates a new RSA key pair and X.509 certificate for the witness
func (wm *WitnessManager) InitCertificate() error {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	wm.privateKey = privateKey
	wm.publicKey = &privateKey.PublicKey

	// Create X.509 certificate for mTLS
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   wm.witnessID,
			Organization: []string{"Lottery Transparency Log"},
			OrganizationalUnit: []string{"Witness"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Valid for 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, wm.publicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Save certificate and private key in a single PEM file for TLS
	certKeyPath := filepath.Join(wm.witnessDir, "witness-cert.pem")
	certKeyFile, err := os.Create(certKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certKeyFile.Close()

	// Write certificate
	if err := pem.Encode(certKeyFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(certKeyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Save public key separately for signature verification
	pubKeyPath := filepath.Join(wm.witnessDir, "witness-pub.pem")
	pubKeyFile, err := os.Create(pubKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer pubKeyFile.Close()

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(wm.publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	if err := pem.Encode(pubKeyFile, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// LoadCertificate loads the witness's key pair from disk
func (wm *WitnessManager) LoadCertificate() error {
	certPath := filepath.Join(wm.witnessDir, "witness-cert.pem")
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	// Parse both certificate and private key from the PEM file
	var certBlock, keyBlock *pem.Block
	remaining := certData
	
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		
		if block.Type == "CERTIFICATE" {
			certBlock = block
		} else if block.Type == "RSA PRIVATE KEY" {
			keyBlock = block
		}
		
		remaining = rest
	}

	if certBlock == nil {
		return fmt.Errorf("no certificate found in PEM file")
	}
	if keyBlock == nil {
		return fmt.Errorf("no private key found in PEM file")
	}

	// Parse the private key
	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	wm.privateKey = privateKey
	wm.publicKey = &privateKey.PublicKey

	return nil
}

// ObserveTree observes and signs the current tree state
func (wm *WitnessManager) ObserveTree(logDir string) error {
	if wm.privateKey == nil {
		if err := wm.LoadCertificate(); err != nil {
			return fmt.Errorf("certificate not loaded: %w", err)
		}
	}

	// Get current tree state
	ll := &LotteryLog{dataDir: logDir}
	treeSize, err := ll.GetTreeSize()
	if err != nil {
		return fmt.Errorf("failed to get tree size: %w", err)
	}

	if treeSize == 0 {
		return fmt.Errorf("no draws to observe")
	}

	treeHash, err := ll.GetTreeHash()
	if err != nil {
		return fmt.Errorf("failed to get tree hash: %w", err)
	}

	// Create witnessed state
	state := WitnessedState{
		TreeSize:  treeSize,
		TreeHash:  fmt.Sprintf("%x", treeHash[:]),
		Timestamp: time.Now(),
		WitnessID: wm.witnessID,
	}

	// Sign the state
	message := fmt.Sprintf("%d:%s:%s", state.TreeSize, state.TreeHash, state.WitnessID)
	hashed := sha256.Sum256([]byte(message))

	signature, err := rsa.SignPKCS1v15(rand.Reader, wm.privateKey, 0, hashed[:])
	if err != nil {
		return fmt.Errorf("failed to sign state: %w", err)
	}

	state.Signature = hex.EncodeToString(signature)

	// Save witnessed state
	if err := wm.saveWitnessedState(state); err != nil {
		return fmt.Errorf("failed to save witnessed state: %w", err)
	}

	return nil
}

// ObserveRemoteTree observes and signs a tree state received from a server
// This is used in distributed mode where the witness doesn't have access to the main log
// Returns the witnessed state including the signature
func (wm *WitnessManager) ObserveRemoteTree(treeSize int64, treeHash string) (*WitnessedState, error) {
	if wm.privateKey == nil {
		if err := wm.LoadCertificate(); err != nil {
			return nil, fmt.Errorf("certificate not loaded: %w", err)
		}
	}

	// Create witnessed state
	state := WitnessedState{
		TreeSize:  treeSize,
		TreeHash:  treeHash,
		Timestamp: time.Now(),
		WitnessID: wm.witnessID,
	}

	// Sign the state
	message := fmt.Sprintf("%d:%s:%s", state.TreeSize, state.TreeHash, state.WitnessID)
	hashed := sha256.Sum256([]byte(message))

	signature, err := rsa.SignPKCS1v15(rand.Reader, wm.privateKey, 0, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign state: %w", err)
	}

	state.Signature = hex.EncodeToString(signature)

	// Save to witness's append-only log
	if err := wm.saveWitnessedState(state); err != nil {
		return nil, fmt.Errorf("failed to save witnessed state: %w", err)
	}

	return &state, nil
}

// saveWitnessedState appends a witnessed state to the witness log
func (wm *WitnessManager) saveWitnessedState(state WitnessedState) error {
	statesPath := filepath.Join(wm.witnessDir, "witnessed-states.json")

	var states []WitnessedState

	// Load existing states if file exists
	if data, err := os.ReadFile(statesPath); err == nil {
		if err := json.Unmarshal(data, &states); err != nil {
			return fmt.Errorf("failed to parse existing states: %w", err)
		}
	}

	// Append new state
	states = append(states, state)

	// Save back to disk
	data, err := json.MarshalIndent(states, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal states: %w", err)
	}

	if err := os.WriteFile(statesPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write states file: %w", err)
	}

	return nil
}

// ListWitnessedStates returns all witnessed states
func (wm *WitnessManager) ListWitnessedStates() ([]WitnessedState, error) {
	statesPath := filepath.Join(wm.witnessDir, "witnessed-states.json")

	data, err := os.ReadFile(statesPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []WitnessedState{}, nil
		}
		return nil, fmt.Errorf("failed to read states file: %w", err)
	}

	var states []WitnessedState
	if err := json.Unmarshal(data, &states); err != nil {
		return nil, fmt.Errorf("failed to parse states: %w", err)
	}

	return states, nil
}

// VerifySignature verifies a witnessed state's signature
func (wm *WitnessManager) VerifySignature(state WitnessedState) error {
	if wm.publicKey == nil {
		if err := wm.LoadCertificate(); err != nil {
			return fmt.Errorf("certificate not loaded: %w", err)
		}
	}

	// Reconstruct the message
	message := fmt.Sprintf("%d:%s:%s", state.TreeSize, state.TreeHash, state.WitnessID)
	hashed := sha256.Sum256([]byte(message))

	// Decode signature
	signature, err := hex.DecodeString(state.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Verify signature
	if err := rsa.VerifyPKCS1v15(wm.publicKey, 0, hashed[:], signature); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// VerifyConsistency verifies consistency between two witnessed states
func (wm *WitnessManager) VerifyConsistency(oldState, newState WitnessedState, logDir string) error {
	if oldState.TreeSize >= newState.TreeSize {
		return fmt.Errorf("old state must have smaller tree size than new state")
	}

	// Parse tree hashes
	oldHash, err := hex.DecodeString(oldState.TreeHash)
	if err != nil {
		return fmt.Errorf("failed to parse old tree hash: %w", err)
	}
	if len(oldHash) != 32 {
		return fmt.Errorf("invalid old tree hash length")
	}

	newHash, err := hex.DecodeString(newState.TreeHash)
	if err != nil {
		return fmt.Errorf("failed to parse new tree hash: %w", err)
	}
	if len(newHash) != 32 {
		return fmt.Errorf("invalid new tree hash length")
	}

	var oldTreeHash, newTreeHash tlog.Hash
	copy(oldTreeHash[:], oldHash)
	copy(newTreeHash[:], newHash)

	// Generate consistency proof
	hr := &hashReader{dataDir: logDir, size: newState.TreeSize}

	proof, err := tlog.ProveTree(newState.TreeSize, oldState.TreeSize, hr)
	if err != nil {
		return fmt.Errorf("failed to generate consistency proof: %w", err)
	}

	// Verify proof
	if err := tlog.CheckTree(proof, newState.TreeSize, newTreeHash, oldState.TreeSize, oldTreeHash); err != nil {
		return fmt.Errorf("consistency check failed: %w", err)
	}

	return nil
}

// ExportPublicKey exports the witness's public key for sharing
func (wm *WitnessManager) ExportPublicKey() (string, error) {
	if wm.publicKey == nil {
		if err := wm.LoadCertificate(); err != nil {
			return "", fmt.Errorf("certificate not loaded: %w", err)
		}
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(wm.publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return string(pubKeyPEM), nil
}

// LoadPublicKey loads a witness's public key from PEM string for verification
func LoadPublicKeyFromPEM(pemString string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPubKey, nil
}
