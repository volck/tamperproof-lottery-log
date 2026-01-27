package cmd

import (
	"encoding/json"
	"fmt"
	"lottery-tlog/tlog"
	"os"

	"github.com/spf13/cobra"
	tliblog "golang.org/x/mod/sumdb/tlog"
)

var (
	drawIndex   int64
	outputFile  string
	proofFile   string
	drawFile    string
	treeSize    int64
	treeHashHex string
)

var proveInclusionCmd = &cobra.Command{
	Use:   "inclusion-prove",
	Short: "Generate an inclusion proof for a draw",
	Long: `Generate a cryptographic proof that a specific draw exists in the tree.
	
This proof can be verified by anyone without needing the entire log.`,
	SilenceUsage: true,
	RunE:         runProveInclusion,
}

var verifyInclusionCmd = &cobra.Command{
	Use:   "inclusion-verify",
	Short: "Verify an inclusion proof for a draw",
	Long: `Verify that a draw exists in the tree using only the proof, draw data, and tree hash.
	
Does not require access to the full log.`,
	SilenceUsage: true,
	RunE:         runVerifyInclusion,
}

func init() {
	proveInclusionCmd.Flags().Int64Var(&drawIndex, "index", 0, "Index of the draw to prove (required)")
	proveInclusionCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for proof (default: stdout)")
	proveInclusionCmd.MarkFlagRequired("index")

	verifyInclusionCmd.Flags().StringVar(&drawFile, "draw-file", "", "JSON file containing the draw data (required)")
	verifyInclusionCmd.Flags().Int64Var(&drawIndex, "index", 0, "Index of the draw (required)")
	verifyInclusionCmd.Flags().Int64Var(&treeSize, "tree-size", 0, "Size of the tree (required)")
	verifyInclusionCmd.Flags().StringVar(&treeHashHex, "tree-hash", "", "Tree root hash in hex (required)")
	verifyInclusionCmd.Flags().StringVar(&proofFile, "proof", "", "File containing the proof (required)")
	verifyInclusionCmd.MarkFlagRequired("draw-file")
	verifyInclusionCmd.MarkFlagRequired("index")
	verifyInclusionCmd.MarkFlagRequired("tree-size")
	verifyInclusionCmd.MarkFlagRequired("tree-hash")
	verifyInclusionCmd.MarkFlagRequired("proof")
}

func runProveInclusion(cmd *cobra.Command, args []string) error {
	lotteryLog, cleanup, err := createLotteryLog()
	if err != nil {
		return fmt.Errorf("failed to create lottery log: %w", err)
	}
	defer cleanup()

	size, err := lotteryLog.GetTreeSize()
	if err != nil {
		return fmt.Errorf("failed to get tree size: %w", err)
	}

	if drawIndex < 0 || drawIndex >= size {
		return fmt.Errorf("index %d out of range [0, %d)", drawIndex, size)
	}

	// Get the draw to include in the proof output
	draw, err := lotteryLog.GetDraw(drawIndex)
	if err != nil {
		return fmt.Errorf("failed to get draw: %w", err)
	}

	// Generate the inclusion proof
	hr := &hashReader{dataDir: getDataDir(), size: size}
	recordProof, err := tliblog.ProveRecord(size, drawIndex, hr)
	if err != nil {
		return fmt.Errorf("failed to generate proof: %w", err)
	}

	treeHash, err := lotteryLog.GetTreeHash(size)
	if err != nil {
		return fmt.Errorf("failed to get tree hash: %w", err)
	}

	// Create proof output
	proofOutput := struct {
		Draw     *tlog.LotteryDraw `json:"draw"`
		Index    int64             `json:"index"`
		TreeSize int64             `json:"tree_size"`
		TreeHash string            `json:"tree_hash"`
		Proof    []string          `json:"proof"`
	}{
		Draw:     draw,
		Index:    drawIndex,
		TreeSize: size,
		TreeHash: fmt.Sprintf("%x", treeHash[:]), // Use treeHash[:] to get byte slice
		Proof:    hashesToHexStrings(recordProof),
	}

	jsonData, err := json.MarshalIndent(proofOutput, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal proof: %w", err)
	}

	// Write to file or stdout
	if outputFile != "" {
		if err := os.WriteFile(outputFile, jsonData, 0644); err != nil {
			return fmt.Errorf("failed to write proof file: %w", err)
		}
		fmt.Printf("✓ Inclusion proof generated\n")
		fmt.Printf("  Draw Index: %d\n", drawIndex)
		fmt.Printf("  Tree Size: %d\n", size)
		fmt.Printf("  Proof saved to: %s\n", outputFile)
	} else {
		fmt.Println(string(jsonData))
	}

	return nil
}

func runVerifyInclusion(cmd *cobra.Command, args []string) error {
	// Read draw data
	drawData, err := os.ReadFile(drawFile)
	if err != nil {
		return fmt.Errorf("failed to read draw file: %w", err)
	}

	var draw tlog.LotteryDraw
	if err := json.Unmarshal(drawData, &draw); err != nil {
		return fmt.Errorf("failed to unmarshal draw: %w", err)
	}

	// Read proof
	proofData, err := os.ReadFile(proofFile)
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

	// Parse tree hash from hex string
	var treeHash tliblog.Hash
	hashBytes := make([]byte, 32)
	n, err := fmt.Sscanf(treeHashHex, "%64x", &hashBytes)
	if err != nil || n == 0 {
		return fmt.Errorf("failed to parse tree hash (expected 64 hex chars): %w", err)
	}
	copy(treeHash[:], hashBytes)

	// Compute the record hash
	recordData, err := json.Marshal(draw)
	if err != nil {
		return fmt.Errorf("failed to marshal draw: %w", err)
	}

	recordHash := tliblog.RecordHash(recordData)

	// Verify the proof
	err = tliblog.CheckRecord(proof, treeSize, treeHash, drawIndex, recordHash)
	if err != nil {
		fmt.Printf("✗ Inclusion proof verification failed: %v\n", err)
		return err
	}

	fmt.Printf("✓ Inclusion proof verified successfully\n")
	fmt.Printf("  Seq No: %d\n", draw.SeqNo)
	fmt.Printf("  Code: %d | %s\n", draw.Message.Code, draw.Message.Text)
	fmt.Printf("  Index: %d\n", drawIndex)
	fmt.Printf("  Tree Size: %d\n", treeSize)

	return nil
}

// hashReader implements tlog.HashReader interface for proof generation
type hashReader struct {
	dataDir string
	size    int64
}

func (hr *hashReader) ReadHashes(indexes []int64) ([]tliblog.Hash, error) {
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
