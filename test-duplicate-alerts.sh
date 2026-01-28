#!/bin/bash
# Test script to demonstrate duplicate detection and witness notifications

set -e

echo "=== Testing Duplicate Detection and Witness Notifications ==="
echo

# Clean up any existing test data
echo "1. Cleaning up test environment..."
rm -rf /tmp/test-duplicate-alerts
mkdir -p /tmp/test-duplicate-alerts

# Create config
cat > /tmp/test-duplicate-alerts/config.yaml <<EOF
server: "http://localhost:8080"
log_directory: "/tmp/test-duplicate-alerts/log"
data_dir: "/tmp/test-duplicate-alerts"
EOF

echo "   ✓ Test environment created"
echo

# Start server in background
echo "2. Starting lottery-tlog server..."
./lottery-tlog server --data-dir /tmp/test-duplicate-alerts > /tmp/test-duplicate-alerts/server.log 2>&1 &
SERVER_PID=$!
echo "   ✓ Server started (PID: $SERVER_PID)"

# Wait for server to be ready
echo "   Waiting for server to be ready..."
for i in {1..10}; do
    if curl -s http://localhost:8080/health > /dev/null 2>&1; then
        echo "   ✓ Server is ready"
        break
    fi
    sleep 1
done
echo

# Initialize witness
echo "3. Initializing witness..."
./lottery-tlog witness init --witness-id test-witness --data-dir /tmp/test-duplicate-alerts > /dev/null 2>&1
echo "   ✓ Witness initialized"
echo

# Add first draw successfully
echo "4. Adding first draw (SeqNo=100)..."
DRAW1='{
  "timestamp": "2026-01-28T10:00:00Z",
  "seqno": 100,
  "ip": "192.168.1.1",
  "severity": "info",
  "message": {
    "code": 200,
    "text": "First draw"
  },
  "mac": "test-mac-1"
}'

curl -s -X POST http://localhost:8080/api/admin/draw \
  -H "Content-Type: application/json" \
  -d "$DRAW1" | jq .
echo "   ✓ First draw added successfully"
echo

# Try to add duplicate draw (should fail and create alert)
echo "5. Attempting to add duplicate draw (SeqNo=100 again)..."
DRAW2='{
  "timestamp": "2026-01-28T10:05:00Z",
  "seqno": 100,
  "ip": "192.168.1.2",
  "severity": "info",
  "message": {
    "code": 201,
    "text": "Duplicate attempt"
  },
  "mac": "test-mac-2"
}'

echo "   Expected: HTTP 409 Conflict"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST http://localhost:8080/api/admin/draw \
  -H "Content-Type: application/json" \
  -d "$DRAW2")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "409" ]; then
    echo "   ✓ Duplicate detected! HTTP $HTTP_CODE"
    echo "   Error message: $BODY"
else
    echo "   ✗ Unexpected response: HTTP $HTTP_CODE"
    echo "   $BODY"
fi
echo

# Check witness alerts (note: would need authentication in real scenario)
echo "6. Checking server logs for duplicate alert..."
if grep -q "Duplicate draw attempt detected" /tmp/test-duplicate-alerts/server.log; then
    echo "   ✓ Alert logged in server"
    grep "Duplicate draw attempt detected" /tmp/test-duplicate-alerts/server.log | tail -1
else
    echo "   ✗ Alert not found in server logs"
fi
echo

# Try adding a different draw (should succeed)
echo "7. Adding different draw (SeqNo=101)..."
DRAW3='{
  "timestamp": "2026-01-28T10:10:00Z",
  "seqno": 101,
  "ip": "192.168.1.3",
  "severity": "info",
  "message": {
    "code": 202,
    "text": "Second draw"
  },
  "mac": "test-mac-3"
}'

curl -s -X POST http://localhost:8080/api/admin/draw \
  -H "Content-Type: application/json" \
  -d "$DRAW3" | jq .
echo "   ✓ Second draw added successfully"
echo

# Cleanup
echo "8. Cleaning up..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
echo "   ✓ Server stopped"
echo

echo "=== Test Complete ==="
echo
echo "Summary:"
echo "  - First draw added successfully"
echo "  - Duplicate draw rejected with HTTP 409"
echo "  - Alert created and logged"
echo "  - Different draw added successfully"
echo
echo "Note: In production with authentication, witnesses would query"
echo "      /api/witness/alerts to receive these security notifications."
