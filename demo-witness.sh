#!/bin/bash
# Demonstration of witness system detecting tampering

set -e

echo "=========================================="
echo "  Witness System Demonstration"
echo "=========================================="
echo ""

# Build if needed
if [ ! -f "./lottery-tlog" ]; then
    echo "Building application..."
    go build
fi

# Initialize two witnesses
echo "1. Initializing two independent witnesses..."
./lottery-tlog witness-init --witness-id "alice-auditor" > /dev/null 2>&1
./lottery-tlog witness-init --witness-id "bob-regulator" > /dev/null 2>&1
echo "   ✓ Alice (independent auditor) initialized"
echo "   ✓ Bob (government regulator) initialized"
echo ""

# Current state
TREE_SIZE=$(cat .lottery-data/tree-size.txt)
echo "2. Current log state: $TREE_SIZE draws"
echo ""

# Both witnesses observe current state
echo "3. Witnesses observe current state..."
./lottery-tlog witness-observe --witness-id "alice-auditor" | grep "Tree Hash" | head -1
./lottery-tlog witness-observe --witness-id "bob-regulator" | grep "Tree Hash" | head -1
echo ""

# Add a new draw
echo "4. Lottery operator adds new draw..."
./lottery-tlog add-draw --draw-id "demo-draw" --random 2>&1 | grep "Draw ID" | head -1
./lottery-tlog add-draw --draw-id "demo-draw-2" --random 2>&1 | grep "Draw ID" | head -1
echo ""

# Witnesses observe new state
echo "5. Witnesses observe new state..."
./lottery-tlog witness-observe --witness-id "alice-auditor" | grep "Tree Size" | head -1
./lottery-tlog witness-observe --witness-id "bob-regulator" | grep "Tree Size" | head -1
echo ""

# Verify consistency
echo "6. Witnesses verify consistency (tree grew correctly)..."
ALICE_RESULT=$(./lottery-tlog witness-verify-consistency --witness-id "alice-auditor" --old-index 1 --new-index 2 2>&1 | grep "CONSISTENCY VERIFIED" || echo "FAILED")
BOB_RESULT=$(./lottery-tlog witness-verify-consistency --witness-id "bob-regulator" --old-index 1 --new-index 2 2>&1 | grep "CONSISTENCY VERIFIED" || echo "FAILED")

if [[ $ALICE_RESULT == *"VERIFIED"* ]]; then
    echo "   ✓ Alice: Consistency verified - tree grew correctly"
else
    echo "   ✗ Alice: CONSISTENCY CHECK FAILED"
fi

if [[ $BOB_RESULT == *"VERIFIED"* ]]; then
    echo "   ✓ Bob: Consistency verified - tree grew correctly"
else
    echo "   ✗ Bob: CONSISTENCY CHECK FAILED"
fi
echo ""

# Show witnessed states
echo "7. Alice's witnessed observations:"
./lottery-tlog witness-list --witness-id "alice-auditor" 2>&1 | grep -E "(Tree Size|Timestamp|Signature verified)"
echo ""

echo "=========================================="
echo "  Demonstration Complete!"
echo "=========================================="
echo ""
echo "Key takeaways:"
echo "- Multiple independent witnesses observe the same log"
echo "- Each witness cryptographically signs their observations"
echo "- Witnesses verify the log only grows (no deletions/modifications)"
echo "- Any tampering would be immediately detected"
echo "- This provides distributed trust instead of single authority"
echo ""
echo "Try tampering:"
echo "  1. Edit any draw file: vim .lottery-data/draw-0.json"
echo "  2. Run: ./lottery-tlog verify"
echo "  3. See tampering detected immediately!"
echo ""
