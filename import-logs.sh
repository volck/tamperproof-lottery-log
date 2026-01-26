#!/bin/bash
# Import lottery events from logs.json into the transparency log

set -e

# Clean start
rm -rf .lottery-data

echo "Importing lottery events from logs.json..."
echo "Total events to import: $(wc -l < logs.json)"
echo ""

count=0
errors=0
start_time=$(date +%s)

while IFS= read -r line; do
    count=$((count + 1))
    
    # Save line to temp file
    echo "$line" > /tmp/event-${count}.json
    
    # Import the event
    if ./lottery-tlog add-draw --json-file /tmp/event-${count}.json > /dev/null 2>&1; then
        if [ $((count % 100)) -eq 0 ]; then
            echo "✓ Imported $count events..."
        fi
    else
        echo "✗ Error importing event $count"
        errors=$((errors + 1))
    fi
    
    rm -f /tmp/event-${count}.json
done < logs.json

end_time=$(date +%s)
duration=$((end_time - start_time))

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Import completed!"
echo "  Total events: $count"
echo "  Successful: $((count - errors))"
echo "  Errors: $errors"
echo "  Duration: ${duration}s"
echo ""

# Verify the tree
echo "Verifying tree integrity..."
./lottery-tlog verify

echo ""
echo "Tree status:"
./lottery-tlog status
