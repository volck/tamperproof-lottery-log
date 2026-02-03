//go:build oracle
// +build oracle

package oracle

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"lottery-tlog/tlog"

	tlib "golang.org/x/mod/sumdb/tlog"
)

// LotteryLog implements the lottery transparency log using Oracle blockchain tables
type LotteryLog struct {
	conn   *Connection
	logger *slog.Logger
}

// NewLotteryLog creates a new Oracle-backed lottery log
func NewLotteryLog(conn *Connection, logger *slog.Logger) (*LotteryLog, error) {
	return &LotteryLog{
		conn:   conn,
		logger: logger,
	}, nil
}

// AddDraw adds a new lottery draw to the Oracle blockchain table
func (l *LotteryLog) AddDraw(draw tlog.LotteryDraw) error {
	l.logger.Info("Adding lottery draw to Oracle blockchain",
		"seqno", draw.SeqNo,
		"code", draw.Message.Code,
		"timestamp", draw.Timestamp)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return l.conn.ExecuteInTransaction(ctx, func(tx *sql.Tx) error {
		// Check for duplicate SeqNo
		var existingIndex sql.NullInt64
		err := tx.QueryRowContext(ctx, `
			SELECT draw_index 
			FROM lottery_draws_blockchain 
			WHERE seqno = :1
		`, draw.SeqNo).Scan(&existingIndex)

		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("failed to check for duplicate: %w", err)
		}

		if existingIndex.Valid {
			return fmt.Errorf("duplicate draw: SeqNo %d already exists at index %d", draw.SeqNo, existingIndex.Int64)
		}

		// Get current tree size
		var currentSize int64
		err = tx.QueryRowContext(ctx, `
			SELECT NVL(MAX(draw_index), -1) + 1 
			FROM lottery_draws_blockchain
		`).Scan(&currentSize)
		if err != nil {
			return fmt.Errorf("failed to get current tree size: %w", err)
		}

		// Serialize draw data as JSON
		drawData, err := json.Marshal(draw)
		if err != nil {
			return fmt.Errorf("failed to marshal draw: %w", err)
		}

		// Extract game properties for indexing (may be nil)
		var game, drawNum, subdraw interface{}
		if draw.Message.GameProperties != nil {
			game = draw.Message.GameProperties.Game
			drawNum = draw.Message.GameProperties.Draw
			subdraw = draw.Message.GameProperties.Subdraw
		}

		// Insert the draw into blockchain table
		_, err = tx.ExecContext(ctx, `
			INSERT INTO lottery_draws_blockchain (
				draw_index, timestamp, seqno, ip, severity,
				message_code, message_text, remote_ip,
				game, draw, subdraw, mac, draw_data
			) VALUES (
				:1, :2, :3, :4, :5, :6, :7, :8, :9, :10, :11, :12, :13
			)
		`, currentSize, draw.Timestamp, draw.SeqNo, draw.IP, draw.Severity,
			draw.Message.Code, draw.Message.Text, draw.Message.RemoteIP,
			game, drawNum, subdraw, draw.MAC, string(drawData))
		if err != nil {
			return fmt.Errorf("failed to insert draw: %w", err)
		}

		// Compute and store Merkle tree hashes
		hr := &oracleHashReader{tx: tx, ctx: ctx}
		storedHashes, err := tlib.StoredHashes(currentSize, drawData, hr)
		if err != nil {
			return fmt.Errorf("failed to compute stored hashes: %w", err)
		}

		// Store the new hashes
		startIndex := tlib.StoredHashIndex(0, currentSize)
		for i, hash := range storedHashes {
			hashIndex := startIndex + int64(i)
			level := computeHashLevel(hashIndex, currentSize)

			_, err = tx.ExecContext(ctx, `
				INSERT INTO merkle_hashes_blockchain (hash_index, hash_level, hash_value)
				VALUES (:1, :2, :3)
			`, hashIndex, level, hash[:])
			if err != nil {
				return fmt.Errorf("failed to insert hash at index %d: %w", hashIndex, err)
			}
		}

		// Compute and update tree state
		newSize := currentSize + 1
		treeHash, err := tlib.TreeHash(newSize, hr)
		if err != nil {
			return fmt.Errorf("failed to compute tree hash: %w", err)
		}

		// Mark previous tree state as not current
		_, err = tx.ExecContext(ctx, `
			UPDATE tree_state_blockchain 
			SET is_current = 0 
			WHERE is_current = 1
		`)
		if err != nil {
			return fmt.Errorf("failed to update previous tree state: %w", err)
		}

		// Insert new tree state
		treeHashHex := hex.EncodeToString(treeHash[:])
		_, err = tx.ExecContext(ctx, `
			INSERT INTO tree_state_blockchain (tree_size, tree_hash, is_current)
			VALUES (:1, :2, 1)
		`, newSize, treeHashHex)
		if err != nil {
			return fmt.Errorf("failed to insert tree state: %w", err)
		}

		l.logger.Info("Successfully added draw to Oracle blockchain",
			"index", currentSize,
			"tree_size", newSize,
			"tree_hash", treeHashHex[:16])

		return nil
	})
}

// GetDraw retrieves a lottery draw by index
func (l *LotteryLog) GetDraw(index int64) (*tlog.LotteryDraw, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var drawData string
	err := l.conn.DB().QueryRowContext(ctx, `
		SELECT draw_data 
		FROM lottery_draws_blockchain 
		WHERE draw_index = :1
	`, index).Scan(&drawData)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("draw not found at index %d", index)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query draw: %w", err)
	}

	var draw tlog.LotteryDraw
	if err := json.Unmarshal([]byte(drawData), &draw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal draw: %w", err)
	}

	return &draw, nil
}

// GetTreeSize returns the current size of the transparency log
func (l *LotteryLog) GetTreeSize() (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var size int64
	err := l.conn.DB().QueryRowContext(ctx, `
		SELECT tree_size 
		FROM tree_state_blockchain 
		WHERE is_current = 1
	`).Scan(&size)
	if err == sql.ErrNoRows {
		return 0, nil // No draws yet
	}
	if err != nil {
		return 0, fmt.Errorf("failed to get tree size: %w", err)
	}

	return size, nil
}

// GetTreeHash returns the tree hash for a given tree size
func (l *LotteryLog) GetTreeHash(size int64) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var treeHash string
	err := l.conn.DB().QueryRowContext(ctx, `
		SELECT tree_hash 
		FROM tree_state_blockchain 
		WHERE tree_size = :1
	`, size).Scan(&treeHash)
	if err != nil {
		return "", fmt.Errorf("failed to get tree hash: %w", err)
	}

	return treeHash, nil
}

// ListDraws returns all draws in the specified range
func (l *LotteryLog) ListDraws(startIndex, endIndex int64) ([]*tlog.LotteryDraw, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rows, err := l.conn.DB().QueryContext(ctx, `
		SELECT draw_data 
		FROM lottery_draws_blockchain 
		WHERE draw_index >= :1 AND draw_index < :2
		ORDER BY draw_index
	`, startIndex, endIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to query draws: %w", err)
	}
	defer rows.Close()

	var draws []*tlog.LotteryDraw
	for rows.Next() {
		var drawData string
		if err := rows.Scan(&drawData); err != nil {
			return nil, fmt.Errorf("failed to scan draw: %w", err)
		}

		var draw tlog.LotteryDraw
		if err := json.Unmarshal([]byte(drawData), &draw); err != nil {
			return nil, fmt.Errorf("failed to unmarshal draw: %w", err)
		}

		draws = append(draws, &draw)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating draws: %w", err)
	}

	return draws, nil
}

// AddWitnessCosignature adds a witness cosignature to the blockchain
func (l *LotteryLog) AddWitnessCosignature(cosig tlog.WitnessCosignature) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	signatureData, err := json.Marshal(cosig)
	if err != nil {
		return fmt.Errorf("failed to marshal signature: %w", err)
	}

	_, err = l.conn.DB().ExecContext(ctx, `
		INSERT INTO witness_signatures_blockchain (
			witness_id, tree_size, tree_hash, signature_data
		) VALUES (:1, :2, :3, :4)
	`, cosig.WitnessID, cosig.TreeSize, cosig.TreeHash, string(signatureData))
	if err != nil {
		return fmt.Errorf("failed to insert witness signature: %w", err)
	}

	l.logger.Info("Added witness cosignature",
		"witness_id", cosig.WitnessID,
		"tree_size", cosig.TreeSize)

	return nil
}

// GetLatestWitnessCosignatures returns all witness cosignatures for the current tree state
func (l *LotteryLog) GetLatestWitnessCosignatures() ([]tlog.WitnessCosignature, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get current tree size
	var currentSize int64
	err := l.conn.DB().QueryRowContext(ctx, `
		SELECT tree_size 
		FROM tree_state_blockchain 
		WHERE is_current = 1
	`).Scan(&currentSize)
	if err == sql.ErrNoRows {
		return nil, nil // No tree state yet
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get current tree size: %w", err)
	}

	// Get all witness signatures for this tree size
	rows, err := l.conn.DB().QueryContext(ctx, `
		SELECT signature_data 
		FROM witness_signatures_blockchain 
		WHERE tree_size = :1
		ORDER BY signed_at
	`, currentSize)
	if err != nil {
		return nil, fmt.Errorf("failed to query witness signatures: %w", err)
	}
	defer rows.Close()

	var cosigs []tlog.WitnessCosignature
	for rows.Next() {
		var sigData string
		if err := rows.Scan(&sigData); err != nil {
			return nil, fmt.Errorf("failed to scan signature: %w", err)
		}

		var cosig tlog.WitnessCosignature
		if err := json.Unmarshal([]byte(sigData), &cosig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal signature: %w", err)
		}

		cosigs = append(cosigs, cosig)
	}

	return cosigs, rows.Err()
}

// GetWitnessCosignatures returns all witness cosignatures for a specific tree size
func (l *LotteryLog) GetWitnessCosignatures(treeSize int64) ([]tlog.WitnessCosignature, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get all witness signatures for this tree size
	rows, err := l.conn.DB().QueryContext(ctx, `
		SELECT signature_data 
		FROM witness_signatures_blockchain 
		WHERE tree_size = :1
		ORDER BY signed_at
	`, treeSize)
	if err != nil {
		return nil, fmt.Errorf("failed to query witness signatures: %w", err)
	}
	defer rows.Close()

	var cosigs []tlog.WitnessCosignature
	for rows.Next() {
		var sigData string
		if err := rows.Scan(&sigData); err != nil {
			return nil, fmt.Errorf("failed to scan signature: %w", err)
		}

		var cosig tlog.WitnessCosignature
		if err := json.Unmarshal([]byte(sigData), &cosig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal signature: %w", err)
		}

		cosigs = append(cosigs, cosig)
	}

	return cosigs, rows.Err()
}

// VerifyIntegrity uses Oracle's built-in blockchain verification
func (l *LotteryLog) VerifyIntegrity() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	l.logger.Info("Verifying Oracle blockchain integrity")

	// Verify lottery draws blockchain table
	var drawsValid int
	err := l.conn.DB().QueryRowContext(ctx, `
		SELECT DBMS_BLOCKCHAIN_TABLE.VERIFY_ROWS(
			schema_name => USER,
			table_name => 'LOTTERY_DRAWS_BLOCKCHAIN',
			row_retention_number => NULL
		) FROM DUAL
	`).Scan(&drawsValid)
	if err != nil {
		return fmt.Errorf("failed to verify draws blockchain: %w", err)
	}

	if drawsValid != 1 {
		return fmt.Errorf("lottery draws blockchain verification failed")
	}

	// Verify tree state blockchain table
	var treeStateValid int
	err = l.conn.DB().QueryRowContext(ctx, `
		SELECT DBMS_BLOCKCHAIN_TABLE.VERIFY_ROWS(
			schema_name => USER,
			table_name => 'TREE_STATE_BLOCKCHAIN',
			row_retention_number => NULL
		) FROM DUAL
	`).Scan(&treeStateValid)
	if err != nil {
		return fmt.Errorf("failed to verify tree state blockchain: %w", err)
	}

	if treeStateValid != 1 {
		return fmt.Errorf("tree state blockchain verification failed")
	}

	// Verify witness signatures blockchain table
	var witnessValid int
	err = l.conn.DB().QueryRowContext(ctx, `
		SELECT DBMS_BLOCKCHAIN_TABLE.VERIFY_ROWS(
			schema_name => USER,
			table_name => 'WITNESS_SIGNATURES_BLOCKCHAIN',
			row_retention_number => NULL
		) FROM DUAL
	`).Scan(&witnessValid)
	if err != nil {
		return fmt.Errorf("failed to verify witness signatures blockchain: %w", err)
	}

	if witnessValid != 1 {
		return fmt.Errorf("witness signatures blockchain verification failed")
	}

	// Verify merkle hashes blockchain table
	var hashesValid int
	err = l.conn.DB().QueryRowContext(ctx, `
		SELECT DBMS_BLOCKCHAIN_TABLE.VERIFY_ROWS(
			schema_name => USER,
			table_name => 'MERKLE_HASHES_BLOCKCHAIN',
			row_retention_number => NULL
		) FROM DUAL
	`).Scan(&hashesValid)
	if err != nil {
		return fmt.Errorf("failed to verify merkle hashes blockchain: %w", err)
	}

	if hashesValid != 1 {
		return fmt.Errorf("merkle hashes blockchain verification failed")
	}

	l.logger.Info("Oracle blockchain integrity verification successful")
	return nil
}

// oracleHashReader implements tlog.HashReader for Oracle backend
type oracleHashReader struct {
	tx  *sql.Tx
	ctx context.Context
}

func (r *oracleHashReader) ReadHashes(indexes []int64) ([]tlib.Hash, error) {
	if len(indexes) == 0 {
		return nil, nil
	}

	result := make([]tlib.Hash, len(indexes))

	for i, idx := range indexes {
		var hashValue []byte
		err := r.tx.QueryRowContext(r.ctx, `
			SELECT hash_value 
			FROM merkle_hashes_blockchain 
			WHERE hash_index = :1
		`, idx).Scan(&hashValue)
		if err != nil {
			return nil, fmt.Errorf("failed to read hash at index %d: %w", idx, err)
		}

		if len(hashValue) != 32 {
			return nil, fmt.Errorf("invalid hash size at index %d: got %d bytes", idx, len(hashValue))
		}

		copy(result[i][:], hashValue)
	}

	return result, nil
}

// computeHashLevel computes the level of a hash in the Merkle tree
func computeHashLevel(hashIndex, treeIndex int64) int {
	// This is a simplified version - the actual level computation
	// depends on the tlog algorithm's internal structure
	level := 0
	offset := hashIndex - tlib.StoredHashIndex(0, treeIndex)
	for offset > 0 {
		level++
		offset >>= 1
	}
	return level
}

// GetOracleChainMetadata retrieves Oracle-specific blockchain metadata for a draw
func (l *LotteryLog) GetOracleChainMetadata(index int64) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var (
		instID    sql.NullInt64
		chainID   sql.NullInt64
		seqNum    sql.NullInt64
		createdAt sql.NullTime
		userNum   sql.NullInt64
		hash      sql.NullString
		signature sql.NullString
		sigAlg    sql.NullString
	)

	err := l.conn.DB().QueryRowContext(ctx, `
		SELECT 
			ORABCTAB_INST_ID$,
			ORABCTAB_CHAIN_ID$,
			ORABCTAB_SEQ_NUM$,
			ORABCTAB_CREATION_TIME$,
			ORABCTAB_USER_NUMBER$,
			ORABCTAB_HASH$,
			ORABCTAB_SIGNATURE$,
			ORABCTAB_SIGNATURE_ALG$
		FROM lottery_draws_blockchain
		WHERE draw_index = :1
	`, index).Scan(&instID, &chainID, &seqNum, &createdAt, &userNum, &hash, &signature, &sigAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to get blockchain metadata: %w", err)
	}

	metadata := map[string]interface{}{
		"instance_id":     instID.Int64,
		"chain_id":        chainID.Int64,
		"sequence_number": seqNum.Int64,
		"creation_time":   createdAt.Time,
		"user_number":     userNum.Int64,
		"hash":            hash.String,
		"signature":       signature.String,
		"signature_alg":   sigAlg.String,
	}

	return metadata, nil
}
