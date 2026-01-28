# Lottery Transparency Log - Proof of Concept

A proof of concept demonstrating the use of Go's transparency log implementation (`golang.org/x/mod/sumdb/tlog`) to maintain an append-only, verifiable log of lottery draw records with positional draws.

## Features

- **Transparency Log**: Uses Merkle trees to ensure integrity of lottery draw records
- **Multiple Storage Backends**: 
  - File-based storage for development/testing
  - Oracle 19c blockchain tables for production with cryptographic signing
- **Verifiable**: Cryptographic proofs allow anyone to verify draws without the full log
- **Tamper-Proof**: Any modification to historical draws is immediately detectable
- **Positional Draws**: Records draws as positions (1 to N) with RNG hash tracking
- **Witness System**: External witnesses cosign tree states for additional security
- **CLI Interface**: Built with Cobra for easy command-line interaction
- **Configuration**: Viper-based configuration management
- **Structured Logging**: Uses slog for clear, structured logs

## Storage Backends

### File-Based (Default)
- Simple file-system storage
- Good for development and testing
- No external dependencies

### Oracle 19c Blockchain Tables
- **Immutable blockchain tables** with Oracle's cryptographic signing
- **Built-in tamper detection** at database level
- **Production-grade** with ACID guarantees
- **Automatic row signing** using SHA2_512
- See [Oracle Quick Start Guide](oracle/QUICKSTART.md) for setup

## Installation

### File-Based Backend (No Oracle)

```bash
# Install dependencies
go mod download

# Build without Oracle support (default)
go build -o lottery-tlog

# The binary will use file-based storage by default
```

### Oracle Backend (Optional)

If you want to use Oracle 19c blockchain tables:

```bash
# 1. Install Oracle Instant Client (required for compilation)
# See oracle/QUICKSTART.md for detailed instructions

# 2. Build with Oracle support
go build -tags oracle -o lottery-tlog

# 3. Configure Oracle connection in config.yaml
# storage_backend: "oracle"
# oracle:
#   connection_string: "user/password@host:port/service"
```

**Note**: The default build (`go build`) does NOT require Oracle client libraries. Oracle support is optional and only needed if you want to use Oracle blockchain tables in production.

## Configuration

Edit `config.yaml`:

```yaml
# Storage backend: "file" or "oracle"
storage_backend: "file"  # Use "oracle" for blockchain tables

# File backend uses log_directory
log_directory: ".lottery-data"

# Oracle backend configuration (only needed if using Oracle)
oracle:
  connection_string: "${ORACLE_CONNECTION_STRING}"
  max_open_conns: 25
  # ... see config.yaml for full options
```

## Usage

### Add Draws

```bash
# Add a random draw (position 1-100)
./lottery-tlog add-draw --draw-id "2026-01-10-evening" --random

# Add a specific draw with custom range
./lottery-tlog add-draw --draw-id "special-draw" --position 50 --max-position 200

# Add with RNG hash
./lottery-tlog add-draw --draw-id "draw-001" --position 25 --rng-hash "abc123def456"
```

### List All Draws

```bash
# Basic list
./lottery-tlog list

# Verbose output with timestamps
./lottery-tlog list --verbose
```

### Verify Integrity

```bash
# Verify all draws in the log
./lottery-tlog verify

# Verify specific data directory
./lottery-tlog verify --data-dir /path/to/data
```

### Generate Cryptographic Proofs

#### Inclusion Proofs
Prove a specific draw exists in the tree without sharing the full log:

```bash
# Generate proof
./lottery-tlog prove-inclusion --index 5 -o proof.json

# Anyone can verify with just the proof
./lottery-tlog verify-inclusion \
  --draw-file draw-5.json \
  --index 5 \
  --tree-size 100 \
  --tree-hash abc123... \
  --proof proof.json
```

#### Consistency Proofs
Prove the log grew from size N to M without tampering:

```bash
# Generate proof
./lottery-tlog prove-consistency --old-size 50 --new-size 100 -o consistency.json

# Verify the log grew correctly
./lottery-tlog verify-consistency \
  --old-size 50 \
  --new-size 100 \
  --old-hash abc123... \
  --new-hash def456... \
  --proof consistency.json
```

### Witness System with Certificate Authentication

To prevent tampering by malicious operators, the system includes a witness mechanism where independent parties can observe and cryptographically sign tree states using X.509 certificates.

### Setting Up as a Witness

#### Setting Up as RSA Witness

Initialize yourself as a witness with a unique identifier:

```bash
./lottery-tlog witness-init --witness-id "alice-auditor"
```

This generates:
- RSA 2048-bit key pair (witness certificate)
- Public key for sharing with others
- Stored in `.lottery-data/witnesses/alice-auditor/`

### Keycloak Authentication

Recommended for production with centralized management. See [KEYCLOAK_SETUP.md](KEYCLOAK_SETUP.md) for full guide.

#### Quick Start with Keycloak

1. Start Keycloak:
```bash
docker-compose -f docker-compose-keycloak.yml up -d
```

2. Configure realm and get initial access token (see KEYCLOAK_SETUP.md)

3. Update `config.yaml`:
```yaml
witness_auth_method: "keycloak"
keycloak:
  enabled: true
  url: "http://localhost:8080"
  realm: "lottery-witnesses"
  initial_access_token: "eyJhbG..."
```

4. Register as witness:
```bash
./lottery-tlog witness-register --witness-id "alice-auditor"
```

### Common Operations (Both Methods)

Record and sign the current tree state:

```bash
./lottery-tlog witness-observe --witness-id "alice-auditor"
```

Each observation creates a signed record containing:
- Tree size (number of draws)
- Tree hash (cryptographic commitment to all draws)
- Timestamp of observation
- Digital signature (proof you witnessed this state)

#### Listing Witnessed States

View all states you've observed:

```bash
./lottery-tlog witness-list --witness-id "alice-auditor"
```

#### Monitoring Security Alerts

Witnesses can monitor for suspicious activity such as duplicate draw attempts:

```bash
# Check all security alerts
./lottery-tlog witness alerts --witness-id "alice-auditor"

# Check alerts since a specific time
./lottery-tlog witness alerts --witness-id "alice-auditor" \
  --since "2026-01-28T00:00:00Z"
```

Security alerts include:
- **Duplicate draw attempts** - When someone tries to add a draw with an existing SeqNo
- Source IP address
- User identity (if authenticated)
- Timestamp of the attempt

This helps witnesses detect:
- Malicious actors trying to manipulate the log
- Configuration errors or bugs
- Unauthorized access attempts

#### Verifying Consistency Between States

Verify the tree grew consistently (no rollbacks or tampering):

```bash
./lottery-tlog witness-verify-consistency --witness-id "alice-auditor" \
  --old-index 1 --new-index 3
```

This proves:
- The tree only appended new draws (no deletion)
- Earlier draws remain unchanged
- No history rewriting occurred

#### Publishing Tree Hashes

Log operators should regularly publish tree hashes:

```bash
./lottery-tlog publish-tree-hash
```

Publish this hash through multiple channels:
- Company website
- Social media
- Newspaper announcements
- Blockchain timestamp services

This allows anyone to verify they're seeing the same log history.

#### Security Properties

**Without Witnesses:**
- Malicious operator can delete `.lottery-data/` and regenerate favorable history
- Single point of trust

**With Witnesses:**
- Operator must maintain consistency with all published hashes
- Tampering detected immediately by consistency verification
- Multiple independent witnesses create distributed trust
- Cannot rewrite history without witnesses detecting it

#### Best Practices for Witnesses

1. **Observe regularly** - After each draw or at regular intervals
2. **Save observations offline** - Backup witnessed states separately
3. **Share public keys** - Let others verify your signatures
4. **Cross-check** - Compare tree hashes with other witnesses
5. **Archive proofs** - Keep consistency proofs for audit trails

### Custom Data Directory

```bash
./lottery-tlog --data-dir ./custom-lottery-data add-draw --draw-id "test-1" --random
```

## Attack Vectors and Mitigations

### Potential Attacks

**1. Modify Draw + Hash Together**
- Attack: Edit `draw-N.json` and recalculate `hash-N.bin`
- Detection: Changes tree hash; witnesses detect inconsistency
- Mitigation: Regular witness observations

**2. Rollback Attack**
- Attack: Delete recent draws and lower tree size
- Detection: Consistency proofs fail; witnesses notice size decrease
- Mitigation: Append-only enforcement + witness monitoring

**3. Complete History Rewrite**
- Attack: Delete all data and regenerate with favorable outcomes
- Detection: New tree hash doesn't match witnessed states
- Mitigation: External witnesses holding signed tree hashes

### Defense in Depth

The system provides **tamper-evidence**, not **tamper-proofing**:

1. **Cryptographic hashing** - Any change detectable via tree hash
2. **Inclusion proofs** - Prove specific draw was in tree at specific time
3. **Consistency proofs** - Prove tree only grew (no deletions/changes)
4. **Witness signatures** - Independent parties sign observed states
5. **Public publication** - Tree hashes published to multiple channels
6. **Gossip protocol** - Witnesses compare hashes to detect forks

## How It Works

### Adding Draws
1. Each lottery draw is:
   - Serialized to JSON with position, max_position, RNG hash, and metadata
   - Hashed using SHA-256
   - Added to the transparency log with proper Merkle tree construction
   - Stored with its cryptographic hash for future verification

### Verification
The verify command:
- Reads all stored draws and their hashes
- Re-computes the hash of each draw from the stored data
- Compares against the originally stored hashes
- Builds a Merkle tree and computes the root hash
- Detects any tampering, corruption, or modification

### Cryptographic Proofs
- **Inclusion Proof**: Logarithmic-size proof that a draw exists at a specific index
- **Consistency Proof**: Proof that the tree grew correctly without modifying history
- Both proofs are verifiable without downloading the entire log
- Based on the same technology as Certificate Transparency

### Benefits
- **Append-only**: Old entries cannot be modified without detection
- **Verifiable**: Anyone can verify integrity with cryptographic proofs
- **Efficient**: Merkle tree structure allows O(log n) proof sizes
- **Portable**: File-based storage, no database required
- **Cryptographic Security**: Uses SHA-256 for tamper detection

## Configuration

## Configuration

Edit `config.yaml`:

```yaml
# Storage backend: "file" (default) or "oracle"
storage_backend: "file"

log_directory: ".lottery-data"
log_level: "info"  # debug, info, warn, error

# Oracle configuration (when using Oracle backend)
oracle:
  connection_string: "user/password@hostname:1521/service_name"
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: "5m"
  conn_max_idle_time: "30s"

server:
  host: "localhost"
  port: 8443
  tls:
    cert_file: "certs/server-cert.pem"
    key_file: "certs/server-key.pem"
    ca_file: "certs/ca-cert.pem"
```

### Oracle Backend Setup

For production deployments with Oracle 19c blockchain tables:

1. **Quick Start**: See [oracle/QUICKSTART.md](oracle/QUICKSTART.md) for 5-minute setup
2. **Detailed Docs**: See [oracle/README.md](oracle/README.md) for comprehensive guide
3. **Schema Setup**: Run `sqlplus user/pass@connection @oracle/schema.sql`

Benefits of Oracle backend:
- Database-enforced immutability
- Automatic cryptographic signing (SHA2_512)
- Built-in tamper detection
- ACID guarantees
- Enterprise-grade backup/recovery

## Project Structure

```
.
├── main.go                 # Entry point
├── cmd/
│   ├── root.go            # Root command with backend selection
│   ├── add_draw.go        # Add draw command
│   ├── verify.go          # Verify integrity command
│   ├── list.go            # List draws command
│   ├── prove_inclusion.go # Inclusion proof generation/verification
│   ├── prove_consistency.go # Consistency proof generation/verification
│   ├── witness_*.go       # Witness system commands
│   └── server.go          # TLS server for witness communication
├── tlog/
│   ├── lottery_log.go     # File-based transparency log
│   ├── adapter.go         # Storage backend adapter
│   └── witness.go         # Witness verification logic
├── oracle/
│   ├── connection.go      # Oracle database connection
│   ├── lottery_log.go     # Oracle blockchain implementation
│   ├── schema.sql         # Database schema with blockchain tables
│   ├── SETUP.sql          # Setup instructions
│   ├── QUICKSTART.md      # Quick start guide
│   └── README.md          # Comprehensive documentation
├── server/
│   └── server.go          # TLS server implementation
├── config.yaml            # Configuration file
├── certs/                 # TLS certificates
└── .lottery-data/         # Data directory (file backend only)
    ├── draw-*.json        # Draw records
    ├── hash-*.bin         # Cryptographic hashes
    └── tree-size.txt      # Current tree size
```

## Example Session

```bash
# Add some draws
./lottery-tlog add-draw --draw-id "draw-001" --random
./lottery-tlog add-draw --draw-id "draw-002" --random
./lottery-tlog add-draw --draw-id "draw-003" --random

# List all draws
./lottery-tlog list

# Verify integrity
./lottery-tlog verify

# Generate inclusion proof for draw at index 0
./lottery-tlog prove-inclusion --index 0 -o proof-0.json

# Someone else can verify without accessing your log
./lottery-tlog verify-inclusion \
  --draw-file draw-0.json \
  --index 0 \
  --tree-size 3 \
  --tree-hash <tree_hash_from_proof> \
  --proof proof-0.json

# Try to tamper with a draw file
echo "tampered" >> .lottery-data/draw-0.json

# Verify again - will detect tampering
./lottery-tlog verify
# ✗ Integrity verification failed: hash mismatch at draw 0
```

## Draw Record Format

```json
{
  "draw_id": "draw-001",
  "timestamp": "2026-01-11T10:00:00Z",
  "position": 42,
  "max_position": 100,
  "rng_hash": "18898005abb0592a",
  "draw_type": "regular"
}
```

## Technical Details

- Uses `golang.org/x/mod/sumdb/tlog` for Merkle tree operations
- Each draw gets a SHA-256 hash stored separately using `RecordHash`
- Tree size tracked in `tree-size.txt`
- Tree hash serves as compact proof of entire log state
- Hashes stored using `StoredHashes` API for efficient tree construction
- Any modification to historical entries breaks the hash chain and is detected

## Security Guarantees

- **Tamper Detection**: Any change to draw files is cryptographically detectable
- **Append-Only**: Cannot remove or reorder draws without detection
- **Verifiable Proofs**: Third parties can verify specific draws independently
- **Merkle Tree Security**: Based on collision-resistant hash functions (SHA-256)
- **No Trust Required**: Verification is cryptographic, not based on trust

## License

MIT
