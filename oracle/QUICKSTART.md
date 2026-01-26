# Oracle 19c Integration Quick Start Guide

This guide will help you quickly set up and use the Oracle 19c blockchain backend for the lottery transparency log.

## ⚠️ Important: Build Requirements

To use Oracle backend, you must:
1. **Install Oracle Instant Client** (development libraries)
2. **Build with Oracle tag**: `go build -tags oracle`

Without the Oracle tag, the application will use file-based storage only.

## 🚀 Quick Start (5 minutes)

### 1. Install Oracle Instant Client

**RHEL/CentOS/Fedora:**
```bash
# Download from Oracle website
wget https://download.oracle.com/otn_software/linux/instantclient/2340000/oracle-instantclient-basic-23.4.0.24.05-1.x86_64.rpm
wget https://download.oracle.com/otn_software/linux/instantclient/2340000/oracle-instantclient-devel-23.4.0.24.05-1.x86_64.rpm

# Install
sudo rpm -ivh oracle-instantclient-basic-*.rpm
sudo rpm -ivh oracle-instantclient-devel-*.rpm

# Set environment
export LD_LIBRARY_PATH=/usr/lib/oracle/23/client64/lib:$LD_LIBRARY_PATH
export PATH=/usr/lib/oracle/23/client64/bin:$PATH
```

**Ubuntu/Debian:**
```bash
wget https://download.oracle.com/otn_software/linux/instantclient/1923000/instantclient-basic-linux.x64-19.23.0.0.0dbru.zip
sudo mkdir -p /opt/oracle
sudo unzip instantclient-basic-linux.x64-19.23.0.0.0dbru.zip -d /opt/oracle
export LD_LIBRARY_PATH=/opt/oracle/instantclient_19_23:$LD_LIBRARY_PATH
```

**macOS:**
```bash
brew tap InstantClientTap/instantclient
brew install instantclient-basic
```

### 2. Set Up Oracle Database

```sql
-- Connect as SYSDBA
sqlplus / as sysdba

-- Create user
CREATE USER lottery_user IDENTIFIED BY "MyPassword123!";
GRANT CONNECT, RESOURCE, CREATE TABLE, UNLIMITED TABLESPACE TO lottery_user;

-- Exit and reconnect as lottery_user
exit
sqlplus lottery_user/MyPassword123!@//localhost:1521/ORCLPDB1
```

### 3. Create Schema

```sql
-- Run the schema creation script
@oracle/schema.sql

-- Verify tables were created
SELECT table_name, blockchain FROM user_tables WHERE blockchain = 'YES';
```

### 4. Configure Application

Edit `config.yaml`:
```yaml
storage_backend: "oracle"

oracle:
  connection_string: "lottery_user/MyPassword123!@localhost:1521/ORCLPDB1"
  max_open_conns: 25
  max_idle_conns: 5
```

### 5. Build with Oracle Support

```bash
# Build with Oracle tag (required!)
go build -tags oracle -o lottery-tlog

# Verify it works
./lottery-tlog status
```

### 6. Test It

```bash
# Add a draw
./lottery-tlog add-draw --draw-id "2026-01-21" --random

# List draws
./lottery-tlog list

# Verify Oracle blockchain integrity
./lottery-tlog verify
```

oracle:
  connection_string: "lottery_user/MyPassword123!@localhost:1521/ORCLPDB1"
```

Or set environment variable:
```bash
export ORACLE_CONNECTION_STRING="lottery_user/MyPassword123!@localhost:1521/ORCLPDB1"
```

### 5. Build and Test

```bash
# Install dependencies
go mod download

# Build
go build -o lottery-tlog

# Test connection
./lottery-tlog status

# Add a test draw
./lottery-tlog add-draw --draw-id "TEST-001" --random

# Verify blockchain integrity
./lottery-tlog verify
```

## ✅ Verification

### Application-Level
```bash
./lottery-tlog status
./lottery-tlog verify
./lottery-tlog list
```

### Database-Level
```sql
-- Check blockchain integrity
EXEC verify_blockchain_integrity;

-- View current state
SELECT * FROM v_current_tree_state;

-- View draws with blockchain metadata
SELECT 
    draw_index,
    draw_id,
    position,
    ORABCTAB_HASH$,
    SUBSTR(ORABCTAB_SIGNATURE$, 1, 40) || '...' as signature
FROM lottery_draws_blockchain
ORDER BY draw_index DESC
FETCH FIRST 5 ROWS ONLY;
```

## 🔐 Security Checklist

- [ ] Use strong database password
- [ ] Enable SSL/TLS for database connections
- [ ] Restrict network access to database (firewall)
- [ ] Enable Oracle auditing on blockchain tables
- [ ] Set up regular backups with RMAN
- [ ] Enable Transparent Data Encryption (TDE)
- [ ] Rotate database passwords regularly
- [ ] Monitor database logs for suspicious activity

## 📊 Common Operations

### Add a Draw
```bash
./lottery-tlog add-draw \
    --draw-id "DRAW-2026-001" \
    --position 42 \
    --max-position 100 \
    --rng-hash "abc123def456"
```

### List All Draws
```bash
./lottery-tlog list
```

### Check Status
```bash
./lottery-tlog status
```

### Verify Integrity
```bash
./lottery-tlog verify
```

### Generate Proof
```bash
# Inclusion proof
./lottery-tlog prove-inclusion --index 5

# Consistency proof
./lottery-tlog prove-consistency --old-size 10 --new-size 20
```

## 🐛 Troubleshooting

### "Cannot locate Oracle Client library"
```bash
# Linux
export LD_LIBRARY_PATH=/opt/oracle/instantclient_19_23:$LD_LIBRARY_PATH

# macOS
export DYLD_LIBRARY_PATH=/usr/local/lib:$DYLD_LIBRARY_PATH

# Add to ~/.bashrc or ~/.zshrc for persistence
```

### "TNS:could not resolve connect identifier"
```bash
# Test connection with sqlplus first
sqlplus lottery_user/password@//hostname:1521/service_name

# Check connection string format in config.yaml
```

### "ORA-00439: feature not enabled"
- Oracle blockchain tables require Oracle 19c or later
- Check your Oracle version: `SELECT * FROM v$version;`

### Connection Pool Issues
```yaml
# Adjust in config.yaml
oracle:
  max_open_conns: 50       # Increase if seeing connection timeouts
  max_idle_conns: 10       # Increase for better connection reuse
  conn_max_lifetime: "10m" # Decrease if seeing stale connections
```

## 📈 Performance Tips

1. **Connection Pooling**: Adjust pool size based on load
2. **Indexes**: Schema includes optimized indexes
3. **Statistics**: Run `DBMS_STATS.GATHER_SCHEMA_STATS` regularly
4. **Monitoring**: Use `--log-level debug` to monitor performance

## 🔄 Switching Between Backends

### File → Oracle
1. Export existing data
2. Change `storage_backend: "oracle"` in config
3. Import data (requires custom migration script)

### Oracle → File
1. Change `storage_backend: "file"` in config
2. Export from Oracle if needed

## 📚 Next Steps

- Read [Oracle README](./oracle/README.md) for detailed documentation
- Review [schema.sql](./oracle/schema.sql) for table structures
- Check [SETUP.sql](./oracle/SETUP.sql) for advanced configuration
- Set up monitoring and alerting
- Configure automated backups

## 🆘 Getting Help

1. Check logs: `./lottery-tlog status --log-level debug`
2. Verify Oracle: `sqlplus user/pass@connection_string`
3. Review Oracle alert log
4. Check application logs for errors

## 🎯 Production Checklist

Before deploying to production:

- [ ] Database backups configured (RMAN)
- [ ] SSL/TLS enabled for connections
- [ ] Firewall rules configured
- [ ] Monitoring and alerting set up
- [ ] Audit logging enabled
- [ ] Password rotation policy in place
- [ ] High availability configured (RAC, Data Guard)
- [ ] Disaster recovery plan documented
- [ ] Performance testing completed
- [ ] Security audit performed

## 📞 Support

For Oracle-specific issues:
- Check Oracle documentation
- Review Oracle alert log
- Use Oracle support portal

For application issues:
- Enable debug logging
- Check application logs
- Review configuration
