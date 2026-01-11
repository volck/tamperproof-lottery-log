# Lottery Transparency Log - Proof of Concept

A proof of concept demonstrating the use of Go's transparency log implementation (`golang.org/x/mod/sumdb/tlog`) to maintain an append-only, verifiable log of lottery draw records with positional draws.

## Features

- **Transparency Log**: Uses Merkle trees to ensure integrity of lottery draw records
- **Verifiable**: Cryptographic proofs allow anyone to verify draws without the full log
- **Tamper-Proof**: Any modification to historical draws is immediately detectable
- **Positional Draws**: Records draws as positions (1 to N) with RNG hash tracking
- **CLI Interface**: Built with Cobra for easy command-line interaction
- **Configuration**: Viper-based configuration management
- **Structured Logging**: Uses slog for clear, structured logs

## Installation

```bash
go mod download
go build -o lottery-tlog
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

### Custom Data Directory

```bash
./lottery-tlog --data-dir ./custom-lottery-data add-draw --draw-id "test-1" --random
```

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

Edit `config.yaml`:

```yaml
log_directory: ".lottery-data"
log_level: "info"  # debug, info, warn, error
```

## Project Structure

```
.
├── main.go                 # Entry point
├── cmd/
│   ├── root.go            # Root command with Viper config
│   ├── add_draw.go        # Add draw command
│   ├── verify.go          # Verify integrity command
│   ├── list.go            # List draws command
│   ├── prove_inclusion.go # Inclusion proof generation/verification
│   ├── prove_consistency.go # Consistency proof generation/verification
│   └── proof_utils.go     # Shared proof utilities
├── tlog/
│   └── lottery_log.go     # Transparency log implementation
├── config.yaml            # Configuration file
└── .lottery-data/         # Data directory (created automatically)
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
