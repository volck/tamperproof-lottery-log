# Oracle 19c Blockchain Integration for Tamperproof Lottery Log

This directory contains the Oracle Database 19c blockchain table integration for the lottery transparency log system.

## Overview

Oracle 19c blockchain tables provide:
- **Immutability**: Rows cannot be modified or deleted
- **Cryptographic Signing**: Each transaction is signed by Oracle
- **Chain Verification**: Built-in verification of blockchain integrity
- **Tamper Detection**: Automatic detection of any tampering attempts
- **Retention Policies**: Guaranteed data retention for specified periods

## Architecture

### Blockchain Tables

1. **lottery_draws_blockchain**: Stores all lottery draws
   - Immutable records of each draw
   - Includes Oracle chain metadata (hash, signature, sequence number)
   - NO DELETE, NO DROP for 10 years

2. **tree_state_blockchain**: Stores Merkle tree states
   - Records the tree size and root hash
   - Tracks tree evolution over time

3. **witness_signatures_blockchain**: Stores witness cosignatures
   - External witness signatures on tree states
   - Provides additional verification layer

4. **merkle_hashes_blockchain**: Stores Merkle tree internal hashes
   - Enables cryptographic proof generation
   - Supports inclusion and consistency proofs

### Security Features

- **SHA2_512 Hashing**: All rows are hashed using SHA-512
- **Digital Signatures**: Oracle automatically signs each row
- **Chain Integrity**: Rows are linked in an unbreakable chain
- **Audit Trail**: Complete audit trail with timestamps and user tracking

## Setup Instructions

### Prerequisites

1. Oracle Database 19c or later
2. Database user with blockchain table privileges
3. Go 1.21+ with Oracle Instant Client libraries

### Step 1: Install Oracle Instant Client

**Linux:**
```bash
# Download from Oracle website or use package manager
# For Ubuntu/Debian:
sudo apt-get install oracle-instantclient-basic

# Set environment variables
export LD_LIBRARY_PATH=/usr/lib/oracle/19.x/client64/lib:$LD_LIBRARY_PATH
```

**macOS:**
```bash
brew tap InstantClientTap/instantclient
brew install instantclient-basic
```

**Windows:**
Download and install from Oracle website, then add to PATH.

### Step 2: Create Database User

Connect as SYSDBA and run:
```sql
CREATE USER lottery_user IDENTIFIED BY "SecurePassword123!";
GRANT CONNECT, RESOURCE, CREATE TABLE TO lottery_user;
GRANT UNLIMITED TABLESPACE TO lottery_user;
```

### Step 3: Create Blockchain Schema

```bash
cd oracle
sqlplus lottery_user/SecurePassword123!@//hostname:1521/service_name @schema.sql
```

Or see [SETUP.sql](./SETUP.sql) for detailed instructions.

### Step 4: Configure Application

Update `config.yaml`:
```yaml
storage_backend: "oracle"

oracle:
  connection_string: "lottery_user/SecurePassword123!@hostname:1521/ORCLPDB1"
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: "5m"
  conn_max_idle_time: "30s"
```

Or use environment variable:
```bash
export ORACLE_CONNECTION_STRING="lottery_user/SecurePassword123!@hostname:1521/ORCLPDB1"
```

### Step 5: Install Go Dependencies

```bash
go mod download
go mod tidy
```

### Step 6: Test Connection

```bash
go run main.go status
```

## Usage

All existing commands work transparently with Oracle backend:

```bash
# Add a lottery draw
./lottery-tlog add-draw --draw-id "DRAW-2026-001" --position 42 --max-position 100 --rng-hash "abc123..."

# List all draws
./lottery-tlog list

# Check status
./lottery-tlog status

# Verify integrity (uses Oracle blockchain verification)
./lottery-tlog verify

# Generate inclusion proof
./lottery-tlog prove-inclusion --index 5

# Generate consistency proof
./lottery-tlog prove-consistency --old-size 10 --new-size 20
```

## Oracle-Specific Features

### Blockchain Metadata

Each draw record includes Oracle blockchain metadata:
- `ORABCTAB_INST_ID$`: Database instance ID
- `ORABCTAB_CHAIN_ID$`: Blockchain chain ID
- `ORABCTAB_SEQ_NUM$`: Sequence number in chain
- `ORABCTAB_CREATION_TIME$`: Creation timestamp
- `ORABCTAB_USER_NUMBER$`: User who created the row
- `ORABCTAB_HASH$`: Row hash
- `ORABCTAB_SIGNATURE$`: Digital signature
- `ORABCTAB_SIGNATURE_ALG$`: Signature algorithm

### Verification

Oracle provides built-in verification:
```sql
-- Verify all blockchain tables
EXEC verify_blockchain_integrity;

-- Verify specific table
SELECT DBMS_BLOCKCHAIN_TABLE.VERIFY_ROWS(
    schema_name => USER,
    table_name => 'LOTTERY_DRAWS_BLOCKCHAIN',
    row_retention_number => NULL
) FROM DUAL;
```

The application automatically uses these verification methods when running `./lottery-tlog verify`.

### Views

Convenient views for querying:

```sql
-- Current tree state with witness count
SELECT * FROM v_current_tree_state;

-- Draws with blockchain metadata
SELECT * FROM v_draw_verification
ORDER BY draw_index DESC;
```

## Monitoring

### Check Database Health

```sql
-- Check blockchain tables
SELECT table_name, blockchain, row_retention, row_retention_locked
FROM user_tables
WHERE blockchain = 'YES';

-- Check table sizes
SELECT 
    table_name,
    num_rows,
    ROUND(blocks * 8192 / 1024 / 1024, 2) as size_mb
FROM user_tables
WHERE table_name LIKE '%BLOCKCHAIN'
ORDER BY size_mb DESC;
```

### Monitor Performance

```sql
-- Recent draw activity
SELECT 
    TO_CHAR(created_at, 'YYYY-MM-DD HH24') as hour,
    COUNT(*) as draw_count
FROM lottery_draws_blockchain
WHERE created_at >= SYSDATE - 7
GROUP BY TO_CHAR(created_at, 'YYYY-MM-DD HH24')
ORDER BY hour DESC;

-- Witness activity
SELECT 
    witness_id,
    COUNT(*) as signatures,
    MAX(signed_at) as last_signature
FROM witness_signatures_blockchain
GROUP BY witness_id;
```

## Backup and Recovery

### Using RMAN (Recommended)

```bash
rman target /

RMAN> BACKUP DATABASE PLUS ARCHIVELOG;
RMAN> BACKUP TABLESPACE users;
```

### Using Data Pump

```bash
expdp lottery_user/password \
    DIRECTORY=dpump_dir \
    DUMPFILE=lottery_backup_%U.dmp \
    PARALLEL=4 \
    COMPRESSION=ALL
```

## Security Considerations

1. **Connection Security**
   - Use SSL/TLS for database connections
   - Enable Oracle Network Encryption
   - Use Oracle Connection Manager for additional security

2. **Access Control**
   - Limit network access to database
   - Use strong passwords
   - Enable Oracle Audit
   - Regularly review access logs

3. **Encryption**
   - Enable Transparent Data Encryption (TDE) for tablespaces
   - Encrypt backups
   - Use encrypted connections

4. **Monitoring**
   - Enable auditing on blockchain tables:
   ```sql
   AUDIT SELECT, INSERT ON lottery_user.lottery_draws_blockchain BY ACCESS;
   ```
   - Monitor failed login attempts
   - Set up alerts for unusual activity

## Performance Tuning

### Connection Pool Settings

Adjust in `config.yaml`:
```yaml
oracle:
  max_open_conns: 50        # Increase for high concurrency
  max_idle_conns: 10        # Balance connection reuse
  conn_max_lifetime: "10m"  # Prevent stale connections
  conn_max_idle_time: "1m"  # Release idle connections
```

### Database Tuning

```sql
-- Analyze tables for optimizer
EXEC DBMS_STATS.GATHER_SCHEMA_STATS(USER);

-- Check index usage
SELECT table_name, index_name, num_rows
FROM user_indexes
WHERE table_name LIKE '%BLOCKCHAIN';
```

## Troubleshooting

### Connection Issues

**Error: ORA-12154: TNS:could not resolve the connect identifier**
- Check connection string format
- Verify tnsnames.ora or use easy connect syntax
- Test with sqlplus first

**Error: DPI-1047: Cannot locate a 64-bit Oracle Client library**
- Install Oracle Instant Client
- Set LD_LIBRARY_PATH (Linux) or PATH (Windows)

### Permission Issues

**Error: ORA-01950: no privileges on tablespace**
```sql
GRANT UNLIMITED TABLESPACE TO lottery_user;
```

**Error: ORA-00439: feature not enabled: Blockchain tables**
- Requires Oracle 19c or later
- Check database edition

### Performance Issues

- Monitor connection pool with `--log-level debug`
- Check database performance views:
```sql
SELECT sql_text, executions, elapsed_time
FROM v$sql
WHERE sql_text LIKE '%lottery_draws%'
ORDER BY elapsed_time DESC;
```

## Comparison: File vs Oracle Backend

| Feature | File Backend | Oracle Backend |
|---------|--------------|----------------|
| Immutability | File permissions | Database-enforced |
| Signatures | Application-level | Oracle blockchain signatures |
| Verification | Manual hash checks | Built-in DBMS verification |
| Scalability | Limited | High (database-backed) |
| Concurrency | File locking | ACID transactions |
| Backup | File copies | RMAN, Data Pump |
| Audit Trail | Application logs | Oracle audit |
| Recovery | Manual | Point-in-time recovery |
| Cost | Free | Oracle license required |

## Migration

### File to Oracle

```bash
# Export from file backend
./lottery-tlog list --all > draws_export.json

# Switch to Oracle backend in config
# Import (custom script needed for bulk import)
```

### Oracle to File

```sql
-- Export from Oracle
SELECT draw_data 
FROM lottery_draws_blockchain
ORDER BY draw_index;
```

## Additional Resources

- [Oracle Blockchain Tables Documentation](https://docs.oracle.com/en/database/oracle/oracle-database/19/sqlrf/CREATE-BLOCKCHAIN-TABLE.html)
- [godror Driver Documentation](https://github.com/godror/godror)
- [Oracle Instant Client Download](https://www.oracle.com/database/technologies/instant-client/downloads.html)

## Support

For issues specific to Oracle integration:
1. Check Oracle alert log
2. Enable debug logging: `--log-level debug`
3. Verify blockchain integrity: `./lottery-tlog verify`
4. Check database connectivity: `sqlplus user/pass@connection_string`
