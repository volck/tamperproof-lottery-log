-- Oracle Blockchain Setup Instructions for Lottery Transparency Log

-- Prerequisites:
-- 1. Oracle Database 19c or later with blockchain table feature enabled
-- 2. A database user with appropriate privileges

-- ============================================================================
-- STEP 1: Create database user (if needed)
-- ============================================================================
-- Run as SYSDBA or user with appropriate privileges

-- CREATE USER lottery_user IDENTIFIED BY "YourSecurePassword123!";
-- GRANT CONNECT, RESOURCE TO lottery_user;
-- GRANT CREATE TABLE TO lottery_user;
-- GRANT UNLIMITED TABLESPACE TO lottery_user;

-- ============================================================================
-- STEP 2: Connect as lottery_user and run schema.sql
-- ============================================================================
-- Connect to the database as lottery_user:
-- sqlplus lottery_user/YourSecurePassword123!@//hostname:1521/service_name

-- Then execute the schema creation script:
-- @oracle/schema.sql

-- ============================================================================
-- STEP 3: Verify the installation
-- ============================================================================

-- Check that blockchain tables were created
SELECT table_name, blockchain 
FROM user_tables 
WHERE blockchain = 'YES'
ORDER BY table_name;

-- Expected output:
-- LOTTERY_DRAWS_BLOCKCHAIN
-- MERKLE_HASHES_BLOCKCHAIN
-- TREE_STATE_BLOCKCHAIN
-- WITNESS_SIGNATURES_BLOCKCHAIN

-- Check blockchain table properties
SELECT table_name, row_retention, row_retention_locked
FROM dba_blockchain_tables
WHERE owner = USER;

-- ============================================================================
-- STEP 4: Configure the application
-- ============================================================================

-- Update config.yaml with your Oracle connection details:
--
-- storage_backend: "oracle"
-- oracle:
--   connection_string: "lottery_user/YourSecurePassword123!@hostname:1521/service_name"
--   max_open_conns: 25
--   max_idle_conns: 5
--   conn_max_lifetime: "5m"
--   conn_max_idle_time: "30s"

-- Or set environment variable:
-- export ORACLE_CONNECTION_STRING="lottery_user/YourSecurePassword123!@hostname:1521/service_name"

-- ============================================================================
-- STEP 5: Test the connection
-- ============================================================================

-- From your application directory, run:
-- go run main.go status

-- This should connect to Oracle and show the current state of the lottery log

-- ============================================================================
-- Monitoring and Maintenance
-- ============================================================================

-- Check blockchain integrity
EXEC verify_blockchain_integrity;

-- View current tree state
SELECT * FROM v_current_tree_state;

-- View recent draws with blockchain metadata
SELECT 
    draw_index,
    draw_id,
    position,
    max_position,
    timestamp,
    ORABCTAB_CREATION_TIME$,
    ORABCTAB_HASH$,
    SUBSTR(ORABCTAB_SIGNATURE$, 1, 50) || '...' as signature
FROM lottery_draws_blockchain
ORDER BY draw_index DESC
FETCH FIRST 10 ROWS ONLY;

-- View witness activity
SELECT 
    witness_id,
    COUNT(*) as signature_count,
    MAX(signed_at) as last_signature
FROM witness_signatures_blockchain
GROUP BY witness_id
ORDER BY last_signature DESC;

-- Check table sizes
SELECT 
    table_name,
    num_rows,
    blocks,
    avg_row_len,
    ROUND(blocks * 8192 / 1024 / 1024, 2) as size_mb
FROM user_tables
WHERE table_name LIKE '%BLOCKCHAIN'
ORDER BY table_name;

-- ============================================================================
-- Backup and Recovery
-- ============================================================================

-- Oracle blockchain tables are immutable and automatically protected.
-- Use Oracle RMAN for backup:
--
-- RMAN> BACKUP DATABASE PLUS ARCHIVELOG;

-- For export (logical backup):
-- expdp lottery_user/password DIRECTORY=dpump_dir DUMPFILE=lottery_backup.dmp

-- ============================================================================
-- Security Recommendations
-- ============================================================================

-- 1. Use strong passwords and rotate regularly
-- 2. Enable Oracle Advanced Security (TDE) for encryption at rest
-- 3. Use SSL/TLS for connections (configure Oracle Network encryption)
-- 4. Limit network access using Oracle Connection Manager or firewall rules
-- 5. Enable Oracle Audit to track all access to blockchain tables
-- 6. Regularly review and monitor blockchain integrity
-- 7. Store database backups securely with encryption

-- Enable audit (as SYSDBA):
-- AUDIT SELECT, INSERT ON lottery_user.lottery_draws_blockchain BY ACCESS;
-- AUDIT SELECT, INSERT ON lottery_user.tree_state_blockchain BY ACCESS;
-- AUDIT SELECT, INSERT ON lottery_user.witness_signatures_blockchain BY ACCESS;

-- ============================================================================
-- Troubleshooting
-- ============================================================================

-- If you get ORA-01950: no privileges on tablespace
-- GRANT UNLIMITED TABLESPACE TO lottery_user;

-- If blockchain table creation fails with ORA-00439
-- Ensure you're using Oracle 19c or later with blockchain feature enabled

-- Check Oracle errors in alert log:
-- SELECT value FROM v$diag_info WHERE name = 'Diag Trace';

-- Test connection from application:
-- go run main.go status --log-level debug
