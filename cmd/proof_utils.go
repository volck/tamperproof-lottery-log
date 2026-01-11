package cmd

import (
	"fmt"
	tliblog "golang.org/x/mod/sumdb/tlog"
)

// hashesToHexStrings converts tlog hashes to hex string representation
func hashesToHexStrings(hashes []tliblog.Hash) []string {
	result := make([]string, len(hashes))
	for i, h := range hashes {
		result[i] = fmt.Sprintf("%x", h[:]) // Use h[:] to get byte slice
	}
	return result
}

// hexStringsToHashes converts hex strings back to tlog hashes
func hexStringsToHashes(hexes []string) []tliblog.Hash {
	result := make([]tliblog.Hash, len(hexes))
	for i, hexStr := range hexes {
		hashBytes := make([]byte, 32)
		n, err := fmt.Sscanf(hexStr, "%64x", &hashBytes)
		if err == nil && n > 0 {
			copy(result[i][:], hashBytes)
		}
	}
	return result
}

// hashesToBytes converts tlog hashes to byte slices
func hashesToBytes(hashes []tliblog.Hash) [][]byte {
	result := make([][]byte, len(hashes))
	for i, h := range hashes {
		result[i] = h[:]
	}
	return result
}

// bytesToHashes converts byte slices back to tlog hashes
func bytesToHashes(bytes [][]byte) []tliblog.Hash {
	result := make([]tliblog.Hash, len(bytes))
	for i, b := range bytes {
		copy(result[i][:], b)
	}
	return result
}
