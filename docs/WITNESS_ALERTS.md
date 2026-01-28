# Witness Alert System

The witness alert system provides security monitoring capabilities, allowing witnesses to be notified when suspicious activities occur on the lottery transparency log server.

## Overview

When security events occur (such as duplicate draw attempts), the server:
1. Detects the security event
2. Creates a `SecurityAlert` record
3. Logs the event with full details
4. Stores alerts in memory (last 100)
5. Makes alerts available via API for witnesses to query

## Security Events

### Duplicate Draw Attempts

When someone attempts to add a lottery draw with a SeqNo that already exists in the log:

**Server Response:**
- HTTP 409 Conflict
- Error message: `duplicate draw: SeqNo X already exists at index Y`

**Alert Created:**
```json
{
  "timestamp": "2026-01-28T10:05:23Z",
  "alert_type": "duplicate_draw_attempt",
  "seqno": 100,
  "source": "192.168.1.100:54321",
  "user_email": "admin@example.com",
  "description": "Attempt to add duplicate draw with SeqNo 100"
}
```

**Alert Fields:**
- `timestamp`: When the attempt occurred (RFC3339 format)
- `alert_type`: Type of security event (currently only "duplicate_draw_attempt")
- `seqno`: The SeqNo that was attempted
- `source`: Source IP address and port
- `user_email`: Email of authenticated user (if available, otherwise "unknown")
- `description`: Human-readable description of the event

## API Endpoint

### GET /api/witness/alerts

Query security alerts from the server.

**Authentication:** Required (witness role)

**Query Parameters:**
- `since` (optional): RFC3339 timestamp - only return alerts after this time

**Example Request:**
```bash
curl -X GET "https://lottery-tlog.example.com/api/witness/alerts?since=2026-01-28T00:00:00Z" \
  -H "Authorization: Bearer <token>" \
  -H "X-Witness-ID: witness1"
```

**Example Response:**
```json
{
  "alerts": [
    {
      "timestamp": "2026-01-28T10:05:23Z",
      "alert_type": "duplicate_draw_attempt",
      "seqno": 100,
      "source": "192.168.1.100:54321",
      "user_email": "admin@example.com",
      "description": "Attempt to add duplicate draw with SeqNo 100"
    },
    {
      "timestamp": "2026-01-28T10:12:15Z",
      "alert_type": "duplicate_draw_attempt",
      "seqno": 42,
      "source": "10.0.0.5:39847",
      "user_email": "unknown",
      "description": "Attempt to add duplicate draw with SeqNo 42"
    }
  ],
  "count": 2
}
```

## CLI Usage

### Check All Alerts

```bash
./lottery-tlog witness alerts --witness-id "my-witness"
```

**Output:**
```
Found 2 security alert(s):

TIMESTAMP            TYPE                       SEQNO  USER                 SOURCE              DESCRIPTION
---------            ----                       -----  ----                 ------              -----------
2026-01-28 10:05:23  duplicate_draw_attempt     100    admin@example.com    192.168.1.100:54321 Attempt to add duplicate draw with SeqNo 100
2026-01-28 10:12:15  duplicate_draw_attempt     42     unknown              10.0.0.5:39847      Attempt to add duplicate draw with SeqNo 42
```

### Check Recent Alerts

```bash
# Check alerts in the last hour
./lottery-tlog witness alerts --witness-id "my-witness" \
  --since "2026-01-28T09:00:00Z"

# Check alerts since yesterday
./lottery-tlog witness alerts --witness-id "my-witness" \
  --since "2026-01-27T00:00:00Z"
```

### Configuration

The witness alerts command uses authentication from your config.yaml:

```yaml
# config.yaml
server: "https://lottery-tlog.example.com"
data_dir: ".lottery-data"

# For Keycloak authentication
keycloak_url: "https://keycloak.example.com"
realm: "lottery-realm"
client_id: "lottery-witness"
client_secret: "your-secret"
username: "witness1@example.com"
password: "your-password"
```

## Automated Monitoring

### Polling Script

Witnesses can set up automated monitoring with a simple script:

```bash
#!/bin/bash
# check-alerts.sh

SINCE_FILE=".last-alert-check"

# Get timestamp of last check (or use 1 hour ago as default)
if [ -f "$SINCE_FILE" ]; then
    SINCE=$(cat "$SINCE_FILE")
else
    SINCE=$(date -u -d "1 hour ago" +"%Y-%m-%dT%H:%M:%SZ")
fi

# Check for new alerts
ALERTS=$(./lottery-tlog witness alerts \
    --witness-id "my-witness" \
    --since "$SINCE" 2>/dev/null)

# If alerts found, send notification
if echo "$ALERTS" | grep -q "Found [1-9]"; then
    echo "SECURITY ALERT DETECTED!"
    echo "$ALERTS"
    
    # Send email, Slack message, etc.
    # mail -s "Lottery Log Security Alert" admin@example.com <<< "$ALERTS"
fi

# Update last check timestamp
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$SINCE_FILE"
```

Run via cron:
```cron
# Check for alerts every 15 minutes
*/15 * * * * /path/to/check-alerts.sh
```

## Server Configuration

The server keeps the last 100 alerts in memory. When the limit is reached, older alerts are removed.

**Alert Storage:**
- In-memory (not persisted across restarts)
- Thread-safe with mutex protection
- Bounded at 100 alerts to prevent memory exhaustion

**Future Enhancements:**
- Persistent storage (database or file)
- Configurable alert retention
- Additional alert types (authentication failures, rate limit violations, etc.)
- Alert severity levels
- Webhook notifications

## Security Considerations

### What Alerts Indicate

**Single duplicate attempt:**
- Possible user error (retrying failed request)
- Application bug (double-submit)
- Network retry mechanism

**Multiple duplicate attempts:**
- Potential malicious actor
- Compromised credentials
- System misconfiguration

### Response Actions

When alerts are detected, witnesses should:

1. **Document:** Record the alert details
2. **Investigate:** Check if the source is legitimate
3. **Communicate:** Contact log operator if pattern seems suspicious
4. **Cross-check:** Compare notes with other witnesses
5. **Escalate:** Report to security team if attack is suspected

### Privacy

Alert data includes:
- Source IP addresses (can identify network location)
- User emails (if authenticated)

Witnesses should:
- Treat alert data as confidential
- Follow data protection regulations
- Secure local storage of alert records
- Use encrypted channels when sharing alert information

## Integration with Witness Workflow

### Recommended Workflow

1. **Regular Observation** (observe tree states)
   ```bash
   ./lottery-tlog witness observe --witness-id "my-witness"
   ```

2. **Alert Monitoring** (check for security events)
   ```bash
   ./lottery-tlog witness alerts --witness-id "my-witness"
   ```

3. **Consistency Verification** (verify tree integrity)
   ```bash
   ./lottery-tlog witness verify-consistency --witness-id "my-witness" \
     --old-index 1 --new-index 2
   ```

4. **Quorum Checking** (verify other witnesses agree)
   ```bash
   ./lottery-tlog witness quorum
   ```

### Automated Witness Container

For Docker deployments, modify your witness container to include alert checking:

```dockerfile
# Add monitoring script
COPY check-alerts.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/check-alerts.sh

# Run both observer and alert monitor
CMD ["/bin/sh", "-c", "lottery-tlog witness observe --witness-id $WITNESS_ID & while true; do check-alerts.sh; sleep 900; done"]
```

## Testing

### Manual Test

```bash
# 1. Start server
./lottery-tlog server

# 2. Add a draw
curl -X POST http://localhost:8080/api/admin/draw \
  -H "Content-Type: application/json" \
  -d '{"seqno": 100, "timestamp": "2026-01-28T10:00:00Z", "ip": "1.2.3.4", "severity": "info", "message": {"code": 200, "text": "test"}, "mac": "test"}'

# 3. Try to add duplicate (should fail)
curl -X POST http://localhost:8080/api/admin/draw \
  -H "Content-Type: application/json" \
  -d '{"seqno": 100, "timestamp": "2026-01-28T10:05:00Z", "ip": "1.2.3.4", "severity": "info", "message": {"code": 201, "text": "duplicate"}, "mac": "test2"}'

# 4. Check alerts (requires authentication)
./lottery-tlog witness alerts --witness-id "test-witness"
```

### Automated Test

```bash
./test-duplicate-alerts.sh
```

This script:
1. Sets up a clean test environment
2. Starts a server
3. Adds a valid draw
4. Attempts to add a duplicate
5. Verifies the duplicate was rejected
6. Confirms alert was created
7. Cleans up

## Troubleshooting

### "No security alerts found"

**Possible causes:**
- No duplicate attempts have occurred
- Alerts are older than the `--since` filter
- Server was restarted (alerts are in-memory only)

### Authentication failures

**Possible causes:**
- Invalid credentials in config.yaml
- Expired tokens
- Witness doesn't have "witness" role in Keycloak
- Network connectivity issues

**Solution:**
```bash
# Test authentication first
./lottery-tlog witness observe --witness-id "my-witness"
```

If observe works, alerts should work too (same authentication).

### "server returned status 403"

**Cause:** User doesn't have witness role

**Solution:** Grant witness role in Keycloak admin console

## Future Enhancements

Potential improvements to the alert system:

1. **Additional Alert Types:**
   - Failed authentication attempts
   - Rate limit violations
   - Invalid consistency proofs
   - Unauthorized access attempts
   - Configuration changes

2. **Alert Persistence:**
   - Store alerts in database
   - Survive server restarts
   - Longer retention periods

3. **Alert Severity:**
   - Critical, high, medium, low
   - Filter by severity
   - Different notification channels

4. **Push Notifications:**
   - Webhooks for real-time alerts
   - Email notifications
   - Slack/Teams integration
   - SMS for critical alerts

5. **Alert Aggregation:**
   - Group similar alerts
   - Detect patterns
   - Rate limiting on notifications

6. **Alert Acknowledgment:**
   - Mark alerts as reviewed
   - Add notes/comments
   - Track who investigated

7. **Alert Dashboard:**
   - Web UI for alert monitoring
   - Real-time updates
   - Alert statistics
   - Trend analysis
