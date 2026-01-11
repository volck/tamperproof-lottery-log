# Witness Setup Guide

This guide explains how to set up and operate as an independent witness for the lottery transparency log.

## What is a Witness?

A witness is an independent party that:
- Observes and records tree states (size + hash)
- Cryptographically signs each observation
- Detects tampering or rollback attempts
- Provides distributed trust instead of single authority

## Setup Instructions

### 1. Initialize Your Witness Identity

Choose a unique witness ID (e.g., your organization name or personal identifier):

```bash
./lottery-tlog witness-init --witness-id "your-organization"
```

This generates:
- **Private key**: `~/.lottery-data/witnesses/your-organization/witness-cert.pem` (KEEP SECRET!)
- **Public key**: `~/.lottery-data/witnesses/your-organization/witness-pub.pem` (share this)

**Important**: Backup your private key securely. It proves your identity.

### 2. Share Your Public Key

Export your public key to share with others:

```bash
cat .lottery-data/witnesses/your-organization/witness-pub.pem
```

Publish this key so others can verify your signatures.

### 3. Regular Observations

Observe the tree state regularly (after each draw or on a schedule):

```bash
# After a new draw is announced
./lottery-tlog witness-observe --witness-id "your-organization"
```

Each observation creates a signed record proving:
- You witnessed this specific tree state
- At this timestamp
- With this tree hash

### 4. Verify Consistency

Before each new observation, verify the tree grew correctly:

```bash
# List your observations
./lottery-tlog witness-list --witness-id "your-organization"

# Verify consistency between observations
./lottery-tlog witness-verify-consistency \
  --witness-id "your-organization" \
  --old-index 1 \
  --new-index 2
```

If consistency check fails, the log has been tampered with!

## Automated Monitoring

Create a cron job for automated witnessing:

```bash
# Edit crontab
crontab -e

# Add line to witness every hour
0 * * * * cd /path/to/lottery-tlog && ./lottery-tlog witness-observe --witness-id "your-org" >> /var/log/lottery-witness.log 2>&1
```

## Cross-Witness Verification

Compare tree hashes with other witnesses:

```bash
# Get current tree hash
./lottery-tlog publish-tree-hash

# Share with other witnesses
# If hashes differ at same tree size → fork detected!
```

## Detecting Attacks

### Rollback Attack
```bash
# Witness 1 saw: tree size 1000, hash ABC...
# Witness 2 now sees: tree size 950, hash DEF...
# → ATTACK: Log was rolled back
```

### Fork Attack
```bash
# Witness 1 sees: tree size 1000, hash ABC...
# Witness 2 sees: tree size 1000, hash XYZ...
# → ATTACK: Different histories shown to different witnesses
```

### Modification Attack
```bash
# Before: tree size 1000, hash ABC...
# After modifying draw 500
# New tree size: 1000, hash DEF...
# Consistency proof from old → new: FAILS
# → ATTACK: History was modified
```

## Storage and Backup

Your witnessed states are stored in:
```
.lottery-data/witnesses/your-org/witnessed-states.json
```

**Backup regularly!** This file is your proof of what you witnessed.

## Best Practices

1. **Observe frequently** - At least after each announced draw
2. **Archive offline** - Keep backups of witnessed states on separate systems
3. **Compare hashes** - Regularly check with other witnesses
4. **Automate alerts** - Set up notifications for consistency failures
5. **Publish observations** - Share your witnessed hashes publicly
6. **Verify signatures** - Always check signature validity before trusting a witnessed state

## Security Considerations

### Protecting Your Private Key

- Store in encrypted storage
- Never share or transmit
- Use hardware security module (HSM) for high-value scenarios
- Rotate keys periodically

### Verifying Other Witnesses

Before trusting another witness's observations:

1. Obtain their public key through trusted channel
2. Verify their signature on witnessed states
3. Cross-check tree hashes at same sizes
4. Establish out-of-band communication for emergencies

## Gossip Protocol (Advanced)

For maximum security, witnesses should implement gossip:

```python
# Pseudocode for witness gossip
def gossip_with_peers():
    my_latest = get_latest_witnessed_state()
    
    for peer in peer_witnesses:
        peer_state = peer.get_latest_state()
        
        if peer_state.tree_size == my_latest.tree_size:
            if peer_state.tree_hash != my_latest.tree_hash:
                ALERT("FORK DETECTED with peer", peer)
        
        if peer_state.tree_size < my_latest.tree_size:
            # Check if peer's state is consistent with mine
            verify_consistency(peer_state, my_latest)
```

## Example Witness Workflow

```bash
# Morning: Initialize witness
./lottery-tlog witness-init --witness-id "acme-auditors"

# After Draw #1
# (Log operator publishes: Tree size 1, hash abc123...)
./lottery-tlog witness-observe --witness-id "acme-auditors"

# After Draw #2
# (Log operator publishes: Tree size 2, hash def456...)
./lottery-tlog witness-observe --witness-id "acme-auditors"

# Verify consistency
./lottery-tlog witness-verify-consistency \
  --witness-id "acme-auditors" \
  --old-index 1 \
  --new-index 2
# ✓ CONSISTENCY VERIFIED

# Someone reports tampering - verify all observations
./lottery-tlog witness-list --witness-id "acme-auditors"
# All signatures valid, hashes recorded
```

## Incident Response

If you detect tampering:

1. **Document everything** - Save all witnessed states
2. **Notify other witnesses** - Alert via secure channel
3. **Contact log operator** - Demand explanation
4. **Publish findings** - Make tampering evidence public
5. **Preserve evidence** - Don't delete witness data
6. **Legal action** - If fraud detected, involve authorities

## Contact

For questions about witness operations:
- GitHub Issues: [your-repo]/issues
- Email: security@lottery-company.example
- Emergency: witnesses@lottery-company.example
