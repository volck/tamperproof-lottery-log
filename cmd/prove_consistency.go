package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	tliblog "golang.org/x/mod/sumdb/tlog"
)

var (
	oldSize      int64
	newSize      int64
	oldHashHex   string
	newHashHex   string
	outputFileCP string
	proofFileCP  string
)

var proveConsistencyCmd = &cobra.Command{
	Use:   "prove-consistency",
	Short: "Generate a consistency proof between two tree states",
	Long: `Generate a cryptographic proof that the tree grew consistently from size N to size M.
	
This proves no historical records were modified, only new ones added.`,
	SilenceUsage: true,
	RunE:         runProveConsistency,
}

var verifyConsistencyCmd = &cobra.Command{
	Use:   "verify-consistency",
	Short: "Verify a consistency proof between two tree states",
	Long: `Verify that a tree grew consistently from one state to another.
	
Only requires the two tree sizes, their hashes, and the proof.`,
	SilenceUsage: true,
	RunE:         runVerifyConsistency,
}

func init() {
	rootCmd.AddCommand(proveConsistencyCmd)
	rootCmd.AddCommand(verifyConsistencyCmd)

	proveConsistencyCmd.Flags().Int64Var(&oldSize, "old-size", 0, "Old tree size (required)")
	proveConsistencyCmd.Flags().Int64Var(&newSize, "new-size", 0, "New tree size (leave empty to use current)")
	proveConsistencyCmd.Flags().StringVarP(&outputFileCP, "output", "o", "", "Output file for proof (default: stdout)")
	proveConsistencyCmd.MarkFlagRequired("old-size")

	verifyConsistencyCmd.Flags().Int64Var(&oldSize, "old-size", 0, "Old tree size (required)")
	verifyConsistencyCmd.Flags().Int64Var(&newSize, "new-size", 0, "New tree size (required)")
	verifyConsistencyCmd.Flags().StringVar(&oldHashHex, "old-hash", "", "Old tree hash in hex (required)")
	verifyConsistencyCmd.Flags().StringVar(&newHashHex, "new-hash", "", "New tree hash in hex (required)")
	verifyConsistencyCmd.Flags().StringVar(&proofFileCP, "proof", "", "File containing the proof (required)")
	verifyConsistencyCmd.MarkFlagRequired("old-size")
	verifyConsistencyCmd.MarkFlagRequired("new-size")
	verifyConsistencyCmd.MarkFlagRequired("old-hash")
	verifyConsistencyCmd.MarkFlagRequired("new-hash")
	verifyConsistencyCmd.MarkFlagRequired("proof")
}

func runProveConsistency(cmd *cobra.Command, args []string) error {
	lotteryLog, cleanup, err := createLotteryLog()
	if err != nil {
		return fmt.Errorf("failed to create lottery log: %w", err)
	}
	defer cleanup()

	currentSize, err := lotteryLog.GetTreeSize()
	if err != nil {
		return fmt.Errorf("failed to get tree size: %w", err)
	}

	// Use current size if newSize not specified
	if newSize == 0 {
		newSize = currentSize
	}

	if oldSize <= 0 || oldSize > newSize {
		return fmt.Errorf("invalid sizes: old=%d, new=%d (must be 0 < old <= new)", oldSize, newSize)
	}

	if newSize > currentSize {
		return fmt.Errorf("new size %d exceeds current tree size %d", newSize, currentSize)
	}

	// Generate the consistency proof
	hr := &consistencyHashReader{dataDir: getDataDir()}
	proof, err := tliblog.ProveTree(newSize, oldSize, hr)
	if err != nil {
		return fmt.Errorf("failed to generate consistency proof: %w", err)
	}

	// Compute tree hashes for both states
	oldHash, err := computeTreeHashAtSize(getDataDir(), oldSize)
	if err != nil {
		return fmt.Errorf("failed to compute old tree hash: %w", err)
	}

	newHash, err := computeTreeHashAtSize(getDataDir(), newSize)
	if err != nil {
		return fmt.Errorf("failed to compute new tree hash: %w", err)
	}

	// Create proof output
	proofOutput := struct {
		OldSize int64    `json:"old_size"`
		NewSize int64    `json:"new_size"`
		OldHash string   `json:"old_hash"`
		NewHash string   `json:"new_hash"`
		Proof   []string `json:"proof"`
	}{
		OldSize: oldSize,
		NewSize: newSize,
		OldHash: fmt.Sprintf("%x", oldHash[:]),
		NewHash: fmt.Sprintf("%x", newHash[:]),
		Proof:   hashesToHexStrings(proof),
	}

	jsonData, err := json.MarshalIndent(proofOutput, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal proof: %w", err)
	}

	// Write to file or stdout
	if outputFileCP != "" {
		if err := os.WriteFile(outputFileCP, jsonData, 0644); err != nil {
			return fmt.Errorf("failed to write proof file: %w", err)
		}
		fmt.Printf("✓ Consistency proof generated\n")
		fmt.Printf("  Old Size: %d\n", oldSize)
		fmt.Printf("  New Size: %d\n", newSize)
		fmt.Printf("  Proof saved to: %s\n", outputFileCP)
	} else {
		fmt.Println(string(jsonData))
	}

	return nil
}

func runVerifyConsistency(cmd *cobra.Command, args []string) error {
	// Read proof
	proofData, err := os.ReadFile(proofFileCP)
	if err != nil {
		return fmt.Errorf("failed to read proof file: %w", err)
	}

	var proofStruct struct {
		Proof []string `json:"proof"`
	}
	if err := json.Unmarshal(proofData, &proofStruct); err != nil {
		return fmt.Errorf("failed to unmarshal proof: %w", err)
	}

	proof := hexStringsToHashes(proofStruct.Proof)

	// Parse tree hashes from hex strings
	var oldHash, newHash tliblog.Hash
	oldHashBytes := make([]byte, 32)
	newHashBytes := make([]byte, 32)

	if _, err := fmt.Sscanf(oldHashHex, "%64x", &oldHashBytes); err != nil {
		return fmt.Errorf("failed to parse old hash: %w", err)
	}
	copy(oldHash[:], oldHashBytes)

	if _, err := fmt.Sscanf(newHashHex, "%64x", &newHashBytes); err != nil {
		return fmt.Errorf("failed to parse new hash: %w", err)
	}
	copy(newHash[:], newHashBytes)

	// Verify the consistency proof
	err = tliblog.CheckTree(proof, newSize, newHash, oldSize, oldHash)
	if err != nil {
		fmt.Printf("✗ Consistency proof verification failed: %v\n", err)
		return err
	}

	fmt.Printf("✓ Consistency proof verified successfully\n")
	fmt.Printf("  Tree grew from size %d to %d\n", oldSize, newSize)
	fmt.Printf("  Added %d new records\n", newSize-oldSize)
	fmt.Printf("  No historical records were modified\n")

	return nil
}

// consistencyHashReader implements tlog.HashReader interface
type consistencyHashReader struct {
	dataDir string
}

func (hr *consistencyHashReader) ReadHashes(indexes []int64) ([]tliblog.Hash, error) {
	result := make([]tliblog.Hash, len(indexes))
	for i, idx := range indexes {
		hashPath := fmt.Sprintf("%s/hash-%d.bin", hr.dataDir, idx)
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

func computeTreeHashAtSize(dataDir string, size int64) (tliblog.Hash, error) {
	if size == 0 {
		return tliblog.Hash{}, nil
	}

	hr := &consistencyHashReader{dataDir: dataDir}
	return tliblog.TreeHash(size, hr)
}
