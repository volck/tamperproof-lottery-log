-- Oracle 19c Blockchain Table Schema for Tamperproof Lottery Log
-- This schema uses Oracle's blockchain table feature with immutability and cryptographic signing

-- ============================================================================
-- Drop existing objects (for clean reinstall)
-- ============================================================================
BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE lottery_draws_blockchain PURGE';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE tree_state_blockchain PURGE';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE witness_signatures_blockchain PURGE';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE merkle_hashes_blockchain PURGE';
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE != -942 THEN
            RAISE;
        END IF;
END;
/

-- ============================================================================
-- Lottery Draws Blockchain Table
-- ============================================================================
CREATE BLOCKCHAIN TABLE lottery_draws_blockchain (
    draw_index NUMBER(19) NOT NULL,
    timestamp TIMESTAMP(6) NOT NULL,
    seqno NUMBER(19) NOT NULL,
    ip VARCHAR2(45) NOT NULL,
    severity VARCHAR2(50) NOT NULL,
    message_code NUMBER(10) NOT NULL,
    message_text VARCHAR2(4000) NOT NULL,
    remote_ip VARCHAR2(45),
    game NUMBER(10),
    draw NUMBER(10),
    subdraw NUMBER(10),
    mac VARCHAR2(512) NOT NULL,
    draw_data CLOB NOT NULL,
    created_at TIMESTAMP(6) DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT pk_lottery_draws PRIMARY KEY (draw_index)
)
NO DROP UNTIL 3650 DAYS IDLE
NO DELETE LOCKED
HASHING USING "SHA2_512" VERSION "v1";

-- Indexes for efficient queries
CREATE INDEX idx_lottery_draws_seqno ON lottery_draws_blockchain(seqno);
CREATE INDEX idx_lottery_draws_timestamp ON lottery_draws_blockchain(timestamp);
CREATE INDEX idx_lottery_draws_code ON lottery_draws_blockchain(message_code);
CREATE INDEX idx_lottery_draws_game ON lottery_draws_blockchain(game, draw, subdraw);
CREATE INDEX idx_lottery_draws_mac ON lottery_draws_blockchain(mac);

COMMENT ON TABLE lottery_draws_blockchain IS 'Immutable blockchain table storing all lottery event logs with cryptographic signatures';
COMMENT ON COLUMN lottery_draws_blockchain.draw_index IS 'Sequential index in the transparency log (0-based)';
COMMENT ON COLUMN lottery_draws_blockchain.seqno IS 'Sequence number of the event';
COMMENT ON COLUMN lottery_draws_blockchain.message_code IS 'Event code (0-330) identifying the type of event';
COMMENT ON COLUMN lottery_draws_blockchain.game IS 'Game identifier (for codes requiring game properties)';
COMMENT ON COLUMN lottery_draws_blockchain.draw IS 'Draw identifier within the game';
COMMENT ON COLUMN lottery_draws_blockchain.subdraw IS 'Subdraw identifier';
COMMENT ON COLUMN lottery_draws_blockchain.mac IS 'Message authentication code for cryptographic verification';
COMMENT ON COLUMN lottery_draws_blockchain.draw_data IS 'Complete event data in JSON format';

-- ============================================================================
-- Tree State Blockchain Table
-- ============================================================================
CREATE BLOCKCHAIN TABLE tree_state_blockchain (
    tree_size NUMBER(19) NOT NULL,
    tree_hash VARCHAR2(128) NOT NULL,
    computed_at TIMESTAMP(6) DEFAULT SYSTIMESTAMP NOT NULL,
    published_at TIMESTAMP(6),
    is_current NUMBER(1) DEFAULT 1 NOT NULL,
    CONSTRAINT pk_tree_state PRIMARY KEY (tree_size),
    CONSTRAINT chk_is_current CHECK (is_current IN (0, 1))
)
NO DROP UNTIL 3650 DAYS IDLE
NO DELETE LOCKED
HASHING USING "SHA2_512" VERSION "v1";

-- Index for current tree state queries
CREATE INDEX idx_tree_state_current ON tree_state_blockchain(is_current, tree_size DESC);

COMMENT ON TABLE tree_state_blockchain IS 'Blockchain table storing Merkle tree state snapshots';
COMMENT ON COLUMN tree_state_blockchain.tree_size IS 'Number of draws in the tree at this state';
COMMENT ON COLUMN tree_state_blockchain.tree_hash IS 'Root hash of the Merkle tree (hex encoded)';
COMMENT ON COLUMN tree_state_blockchain.is_current IS '1 if this is the current tree state, 0 otherwise';

-- ============================================================================
-- Witness Signatures Blockchain Table
-- ============================================================================
CREATE BLOCKCHAIN TABLE witness_signatures_blockchain (
    signature_id NUMBER(19) GENERATED ALWAYS AS IDENTITY,
    witness_id VARCHAR2(255) NOT NULL,
    tree_size NUMBER(19) NOT NULL,
    tree_hash VARCHAR2(128) NOT NULL,
    signature_data CLOB NOT NULL,
    signed_at TIMESTAMP(6) DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT pk_witness_signatures PRIMARY KEY (signature_id)
)
NO DROP UNTIL 3650 DAYS IDLE
NO DELETE LOCKED
HASHING USING "SHA2_512" VERSION "v1";

-- Index for witness cosignature queries
CREATE INDEX idx_witness_sigs_tree ON witness_signatures_blockchain(tree_size, witness_id);
CREATE INDEX idx_witness_sigs_witness ON witness_signatures_blockchain(witness_id, signed_at DESC);

COMMENT ON TABLE witness_signatures_blockchain IS 'Blockchain table storing witness cosignatures on tree states';
COMMENT ON COLUMN witness_signatures_blockchain.witness_id IS 'Unique identifier for the witness';
COMMENT ON COLUMN witness_signatures_blockchain.tree_size IS 'Tree size being witnessed';
COMMENT ON COLUMN witness_signatures_blockchain.signature_data IS 'Cryptographic signature from witness';

-- ============================================================================
-- Merkle Tree Hashes Blockchain Table
-- ============================================================================
CREATE BLOCKCHAIN TABLE merkle_hashes_blockchain (
    hash_index NUMBER(19) NOT NULL,
    hash_level NUMBER(10) NOT NULL,
    hash_value RAW(32) NOT NULL,
    created_at TIMESTAMP(6) DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT pk_merkle_hashes PRIMARY KEY (hash_index)
)
NO DROP UNTIL 3650 DAYS IDLE
NO DELETE LOCKED
HASHING USING "SHA2_512" VERSION "v1";

-- Index for tree hash computation
CREATE INDEX idx_merkle_hashes_level ON merkle_hashes_blockchain(hash_level, hash_index);

COMMENT ON TABLE merkle_hashes_blockchain IS 'Blockchain table storing Merkle tree internal hashes';
COMMENT ON COLUMN merkle_hashes_blockchain.hash_index IS 'Sequential index in the stored hashes array';
COMMENT ON COLUMN merkle_hashes_blockchain.hash_level IS 'Level in the Merkle tree (0 = leaves)';
COMMENT ON COLUMN merkle_hashes_blockchain.hash_value IS 'SHA-256 hash value (32 bytes)';

-- ============================================================================
-- Views for easier querying
-- ============================================================================

-- View to get current tree state with witness signatures
CREATE OR REPLACE VIEW v_current_tree_state AS
SELECT 
    ts.tree_size,
    ts.tree_hash,
    ts.computed_at,
    ts.published_at,
    COUNT(ws.signature_id) as witness_count,
    LISTAGG(ws.witness_id, ',') WITHIN GROUP (ORDER BY ws.signed_at) as witnesses
FROM tree_state_blockchain ts
LEFT JOIN witness_signatures_blockchain ws ON ts.tree_size = ws.tree_size
WHERE ts.is_current = 1
GROUP BY ts.tree_size, ts.tree_hash, ts.computed_at, ts.published_at;

-- View for draw verification
CREATE OR REPLACE VIEW v_draw_verification AS
SELECT 
    ld.draw_index,
    ld.draw_id,
    ld.timestamp,
    ld.position,
    ld.max_position,
    ld.rng_hash,
    ld.draw_type,
    ld.created_at,
    ld.ORABCTAB_INST_ID$,
    ld.ORABCTAB_CHAIN_ID$,
    ld.ORABCTAB_SEQ_NUM$,
    ld.ORABCTAB_CREATION_TIME$,
    ld.ORABCTAB_USER_NUMBER$,
    ld.ORABCTAB_HASH$,
    ld.ORABCTAB_SIGNATURE$,
    ld.ORABCTAB_SIGNATURE_ALG$
FROM lottery_draws_blockchain ld
ORDER BY ld.draw_index;

-- ============================================================================
-- Verification Procedures
-- ============================================================================

-- Verify blockchain integrity
CREATE OR REPLACE PROCEDURE verify_blockchain_integrity AS
    v_count NUMBER;
    v_valid NUMBER;
BEGIN
    -- Verify lottery draws blockchain
    SELECT COUNT(*) INTO v_count FROM lottery_draws_blockchain;
    
    SELECT COUNT(*) INTO v_valid 
    FROM lottery_draws_blockchain
    WHERE DBMS_BLOCKCHAIN_TABLE.VERIFY_ROWS(
        schema_name => USER,
        table_name => 'LOTTERY_DRAWS_BLOCKCHAIN',
        row_retention_number => v_count
    ) = 1;
    
    IF v_valid != v_count THEN
        RAISE_APPLICATION_ERROR(-20001, 'Blockchain integrity verification failed for lottery_draws_blockchain');
    END IF;
    
    DBMS_OUTPUT.PUT_LINE('Blockchain integrity verified: ' || v_count || ' rows valid');
END;
/

-- ============================================================================
-- Grant permissions (adjust as needed for your user)
-- ============================================================================
-- GRANT SELECT, INSERT ON lottery_draws_blockchain TO lottery_app_user;
-- GRANT SELECT, INSERT, UPDATE ON tree_state_blockchain TO lottery_app_user;
-- GRANT SELECT, INSERT ON witness_signatures_blockchain TO lottery_app_user;
-- GRANT SELECT, INSERT ON merkle_hashes_blockchain TO lottery_app_user;
-- GRANT SELECT ON v_current_tree_state TO lottery_app_user;
-- GRANT SELECT ON v_draw_verification TO lottery_app_user;
-- GRANT EXECUTE ON verify_blockchain_integrity TO lottery_app_user;

COMMIT;
