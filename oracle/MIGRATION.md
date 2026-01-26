# Migration Guide: File Backend to Oracle Blockchain

This guide explains how to migrate your lottery transparency log from file-based storage to Oracle 19c blockchain tables.

## Why Migrate?

| Feature | File Backend | Oracle Blockchain |
|---------|--------------|-------------------|
| **Immutability** | File permissions | Database-enforced, cannot be disabled |
| **Signatures** | Application-level | Oracle automatic signing (SHA2_512) |
| **Tampering Detection** | Hash verification | Oracle DBMS built-in verification |
| **Scalability** | Limited by filesystem | Enterprise-grade database |
| **Concurrency** | File locking issues | ACID transactions, multi-user safe |
| **Backup** | Manual file copies | RMAN, Data Pump, point-in-time recovery |
| **Audit Trail** | Application logs only | Full Oracle audit system |
| **Compliance** | Manual | Industry-standard database compliance |

## Prerequisites

Before migrating:

1. ✅ Oracle 19c or later installed and running
2. ✅ Oracle Instant Client installed on application server
3. ✅ Database user created with privileges
4. ✅ Blockchain schema deployed (`oracle/schema.sql`)
5. ✅ Backup of existing file-based data
6. ✅ Network connectivity between app and Oracle

## Migration Steps

### Step 1: Backup Current Data

```bash
# Create backup directory
mkdir -p backup/$(date +%Y%m%d)

# Backup data directory
cp -r .lottery-data backup/$(date +%Y%m%d)/

# Export draws to JSON
./lottery-tlog list --all > backup/$(date +%Y%m%d)/draws_export.json

# Backup configuration
cp config.yaml backup/$(date +%Y%m%d)/
```

### Step 2: Set Up Oracle

```bash
# Navigate to oracle directory
cd oracle

# Connect to Oracle
sqlplus lottery_user/password@//hostname:1521/ORCLPDB1

# Deploy schema
@schema.sql

# Verify tables created
SELECT table_name, blockchain FROM user_tables WHERE blockchain = 'YES';

# Should see:
# LOTTERY_DRAWS_BLOCKCHAIN
# TREE_STATE_BLOCKCHAIN
# WITNESS_SIGNATURES_BLOCKCHAIN
# MERKLE_HASHES_BLOCKCHAIN

exit
```

### Step 3: Configure Application

Update `config.yaml`:

```yaml
# Change backend to Oracle
storage_backend: "oracle"

# Keep file settings for reference/fallback
log_directory: ".lottery-data"
log_level: "info"

# Add Oracle configuration
oracle:
  connection_string: "lottery_user/SecurePass123!@hostname:1521/ORCLPDB1"
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: "5m"
  conn_max_idle_time: "30s"
```

Or use environment variable:
```bash
export ORACLE_CONNECTION_STRING="lottery_user/SecurePass123!@hostname:1521/ORCLPDB1"
```

### Step 4: Test Oracle Connection

```bash
# Rebuild application with Oracle support
go mod download
go build -o lottery-tlog

# Test connection
./lottery-tlog status

# Should show:
# Storage Backend: oracle
# Database: Connected
```

### Step 5: Migrate Data

⚠️ **IMPORTANT**: The Merkle tree structure must be preserved exactly, so draws must be added in the same order.

#### Option A: Manual Re-Entry (Small Datasets)

```bash
# Add draws one by one from your backup
./lottery-tlog add-draw --draw-id "DRAW-001" --position 42 --max-position 100 --rng-hash "abc123"
./lottery-tlog add-draw --draw-id "DRAW-002" --position 15 --max-position 100 --rng-hash "def456"
# ... etc
```

#### Option B: Automated Migration Script (Recommended)

Create `migrate_to_oracle.go`:

```go
package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "lottery-tlog/oracle"
    "lottery-tlog/tlog"
    "os"
    "path/filepath"
    "sort"
    "strconv"
    "strings"
)

func main() {
    // Connect to Oracle
    oracleConfig := oracle.Config{
        ConnectionString: os.Getenv("ORACLE_CONNECTION_STRING"),
        MaxOpenConns:     25,
    }
    
    conn, err := oracle.NewConnection(oracleConfig, slog.Default())
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    oracleLog, err := oracle.NewLotteryLog(conn, slog.Default())
    if err != nil {
        log.Fatal(err)
    }
    
    // Read files from old data directory
    dataDir := ".lottery-data"
    files, err := filepath.Glob(filepath.Join(dataDir, "draw-*.json"))
    if err != nil {
        log.Fatal(err)
    }
    
    // Sort by index
    sort.Slice(files, func(i, j int) bool {
        iIdx := extractIndex(files[i])
        jIdx := extractIndex(files[j])
        return iIdx < jIdx
    })
    
    // Migrate each draw
    for i, file := range files {
        data, err := ioutil.ReadFile(file)
        if err != nil {
            log.Printf("Failed to read %s: %v", file, err)
            continue
        }
        
        var draw tlog.LotteryDraw
        if err := json.Unmarshal(data, &draw); err != nil {
            log.Printf("Failed to unmarshal %s: %v", file, err)
            continue
        }
        
        if err := oracleLog.AddDraw(draw); err != nil {
            log.Printf("Failed to add draw %d: %v", i, err)
            log.Fatal("Migration failed - Oracle database may be inconsistent")
        }
        
        log.Printf("Migrated draw %d: %s", i, draw.DrawID)
    }
    
    fmt.Printf("\n✓ Migration complete: %d draws migrated\n", len(files))
}

func extractIndex(filename string) int {
    base := filepath.Base(filename)
    parts := strings.Split(base, "-")
    if len(parts) < 2 {
        return 0
    }
    idxStr := strings.TrimSuffix(parts[1], ".json")
    idx, _ := strconv.Atoi(idxStr)
    return idx
}
```

Run migration:
```bash
export ORACLE_CONNECTION_STRING="lottery_user/password@//host:1521/service"
go run migrate_to_oracle.go
```

### Step 6: Verify Migration

```bash
# Check draw count matches
./lottery-tlog status

# Verify integrity
./lottery-tlog verify

# List draws and compare with backup
./lottery-tlog list > migration_list.txt
diff backup/$(date +%Y%m%d)/draws_export.json migration_list.txt

# Check Oracle directly
sqlplus lottery_user/password@//host:1521/service <<EOF
SELECT COUNT(*) FROM lottery_draws_blockchain;
SELECT draw_index, draw_id, position FROM lottery_draws_blockchain ORDER BY draw_index;
EXEC verify_blockchain_integrity;
EOF
```

### Step 7: Migrate Witness Signatures

If you have existing witness signatures:

```sql
-- Insert witness signatures from file backup
INSERT INTO witness_signatures_blockchain (
    witness_id, tree_size, tree_hash, signature_data
) VALUES (
    'witness-1', 100, 'abc123...', '{"witness_id":"witness-1",...}'
);
```

### Step 8: Test End-to-End

```bash
# Add a new draw to Oracle
./lottery-tlog add-draw --draw-id "POST-MIGRATION-001" --random

# Verify
./lottery-tlog verify

# Test proofs
./lottery-tlog prove-inclusion --index 0 -o proof.json
./lottery-tlog prove-consistency --old-size 10 --new-size 20
```

## Rollback Plan

If issues occur during migration:

### Emergency Rollback

```yaml
# In config.yaml, change back to file
storage_backend: "file"
```

```bash
# Restore from backup
rm -rf .lottery-data
cp -r backup/$(date +%Y%m%d)/.lottery-data .

# Restart application
./lottery-tlog status
```

### Partial Migration Recovery

If migration partially completed:

```sql
-- Clear Oracle tables (CAUTION!)
TRUNCATE TABLE witness_signatures_blockchain;
TRUNCATE TABLE merkle_hashes_blockchain;
TRUNCATE TABLE tree_state_blockchain;
TRUNCATE TABLE lottery_draws_blockchain;

-- Start migration again from step 5
```

## Post-Migration Checklist

- [ ] All draws migrated (count matches)
- [ ] Integrity verification passes
- [ ] Witness signatures migrated
- [ ] New draws can be added
- [ ] Proofs can be generated
- [ ] Backup strategy for Oracle in place
- [ ] Monitoring configured
- [ ] Old file data archived securely
- [ ] Documentation updated

## Performance Tuning

After migration, tune Oracle for your workload:

```sql
-- Analyze tables for optimizer
EXEC DBMS_STATS.GATHER_SCHEMA_STATS(USER);

-- Check index effectiveness
SELECT table_name, index_name, num_rows
FROM user_indexes
WHERE table_name LIKE '%BLOCKCHAIN';

-- Monitor query performance
SELECT sql_text, executions, elapsed_time
FROM v$sql
WHERE sql_text LIKE '%lottery_draws%'
ORDER BY elapsed_time DESC
FETCH FIRST 10 ROWS ONLY;
```

Adjust connection pool in `config.yaml`:
```yaml
oracle:
  max_open_conns: 50      # Increase for high load
  max_idle_conns: 10      # Balance connection reuse
  conn_max_lifetime: "10m"
```

## Ongoing Operations

### Backups

Set up RMAN backups:
```bash
rman target /
RMAN> BACKUP DATABASE PLUS ARCHIVELOG;
RMAN> BACKUP TABLESPACE users;
```

### Monitoring

```sql
-- Daily checks
SELECT COUNT(*) as total_draws FROM lottery_draws_blockchain;
SELECT * FROM v_current_tree_state;
EXEC verify_blockchain_integrity;

-- Weekly analysis
EXEC DBMS_STATS.GATHER_SCHEMA_STATS(USER);
```

### Maintenance

```sql
-- Check tablespace usage
SELECT 
    tablespace_name,
    ROUND(SUM(bytes)/1024/1024/1024, 2) as size_gb,
    ROUND(SUM(bytes)/1024/1024/1024 * 100 / 
          (SELECT SUM(bytes)/1024/1024/1024 
           FROM dba_data_files 
           WHERE tablespace_name = df.tablespace_name), 2) as pct_used
FROM dba_data_files df
GROUP BY tablespace_name;
```

## Troubleshooting

### "Tree size mismatch after migration"
- Ensure draws were added in exact order
- Check for missing draw files
- Verify no draws were skipped

### "Blockchain verification fails"
- This is CRITICAL - do not proceed
- Restore from backup and retry migration
- Contact Oracle support if blockchain tables are corrupted

### "Connection pool exhausted"
- Increase `max_open_conns` in config
- Check for connection leaks in logs
- Monitor with `SELECT * FROM v$session WHERE username = 'LOTTERY_USER'`

### "Migration script fails halfway"
- DO NOT retry without clearing Oracle tables first
- Merkle tree structure depends on exact order
- Use transaction boundaries in migration script

## Support

For migration assistance:
1. Review logs: `./lottery-tlog status --log-level debug`
2. Check Oracle alert log
3. Verify network connectivity
4. Test with small dataset first

## Best Practices

1. **Test First**: Migrate a copy of data on test environment
2. **Maintain Backups**: Keep file backup until Oracle proven stable
3. **Monitor Closely**: Watch performance for first week
4. **Plan Downtime**: Schedule migration during low-usage period
5. **Document Everything**: Record all steps and any issues
6. **Verify Thoroughly**: Don't trust, verify!
