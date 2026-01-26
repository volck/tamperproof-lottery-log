# Token Lifecycle Management

The lottery transparency log implements comprehensive token and session lifecycle management for secure, long-running operations.

## Overview

```
┌─────────────┐
│   Login     │
│ (OIDC/mTLS) │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│ Session Created │
│  - Access Token │
│  - Refresh Token│
│  - 24h Expiry   │
└──────┬──────────┘
       │
       ▼
┌────────────────────┐
│  Active Session    │
│  - Last Accessed   │
│  - Auto-refresh    │
│  - 30min Idle      │
└──────┬─────────────┘
       │
       ├──> Expired? ──> Cleanup
       │
       ├──> Idle? ────> Cleanup
       │
       └──> Active ───> Continue
```

## Server-Side Lifecycle

### Session Creation

When a user authenticates via OIDC:

```go
Session{
    Email:        "witness1@lottery.org"
    IsAdmin:      false
    IsWitness:    true
    CreatedAt:    2026-01-21 14:00:00
    ExpiresAt:    2026-01-22 14:00:00  // +24 hours
    LastAccessed: 2026-01-21 14:00:00
    RefreshToken: "eyJ..."              // OAuth2 refresh token
}
```

### Session Tracking

On every API request:
1. **Validate session** exists and not expired
2. **Update LastAccessed** timestamp
3. **Check idle timeout** (30 minutes)
4. **Allow request** if valid

### Automatic Cleanup

Background goroutine runs every 5 minutes:

```go
// Removes sessions that are:
- Expired: ExpiresAt < now
- Idle: LastAccessed + 30min < now
```

Cleanup logging:
```
INFO Session cleanup completed
  initial_count=42
  removed=3
  remaining=39
```

### Session Refresh

**Endpoint**: `POST /auth/refresh`

**With Refresh Token** (OIDC):
1. Use OAuth2 refresh token to get new access token
2. Update session.RefreshToken if new one provided
3. Extend session.ExpiresAt by 24 hours
4. Update session.LastAccessed

**Without Refresh Token** (simple extension):
1. Extend session.ExpiresAt by 24 hours  
2. Update session.LastAccessed

```bash
# Refresh session
curl -b cookies.txt https://localhost:8443/auth/refresh
```

Response:
```json
{
  "status": "refreshed",
  "expires_at": "2026-01-22T14:00:00Z"
}
```

## Client-Side Lifecycle (Witness Observer)

### Single Observation

For one-time operations, token obtained and used immediately:

```bash
./lottery-tlog witness-observe \
  --witness-id "witness1" \
  --server "https://localhost:8443" \
  --keycloak-url "https://keycloak.example.com/.../token" \
  --client-id "lottery-api" \
  --username "witness1@lottery.org" \
  --password "password"
```

**Flow**:
1. Authenticate with Keycloak → Get JWT (expires in 15 min)
2. Observe tree state → Use JWT
3. Sign observation → Use JWT
4. Submit signature → Use JWT
5. Done (token discarded)

### Watch Mode (Long-Running)

For continuous monitoring, token needs refresh:

```bash
./lottery-tlog witness-observe \
  --witness-id "witness1" \
  --server "https://localhost:8443" \
  --watch --interval 10s \
  --keycloak-url "$KEYCLOAK_URL" \
  --client-id "$CLIENT_ID" \
  --username "$USERNAME" \
  --password "$PASSWORD"
```

**Current Behavior**:
- Token obtained once at startup
- ⚠️ Token expires after 15 minutes (from Keycloak)
- ⚠️ No automatic refresh implemented
- **Result**: Watch mode fails after token expires

**Recommended Workaround** (until auto-refresh implemented):

**Option 1**: Use session cookies (browser-based)
```javascript
// Web client that automatically refreshes
setInterval(() => {
  fetch('/auth/refresh', {credentials: 'include'});
}, 10 * 60 * 1000); // Every 10 minutes
```

**Option 2**: External token manager
```bash
#!/bin/bash
# token-refresher.sh
while true; do
  # Get new token every 10 minutes
  export TOKEN=$(curl -s $KEYCLOAK_URL \
    -d "grant_type=password" \
    -d "client_id=$CLIENT_ID" \
    -d "username=$USERNAME" \
    -d "password=$PASSWORD" \
    | jq -r .access_token)
  
  sleep 600  # 10 minutes
done
```

**Option 3**: Use refresh tokens directly
```bash
# Get initial tokens
RESPONSE=$(curl -s $KEYCLOAK_URL \
  -d "grant_type=password" \
  -d "client_id=$CLIENT_ID" \
  -d "username=$USERNAME" \
  -d "password=$PASSWORD")

ACCESS_TOKEN=$(echo $RESPONSE | jq -r .access_token)
REFRESH_TOKEN=$(echo $RESPONSE | jq -r .refresh_token)

# Later: Refresh
NEW_RESPONSE=$(curl -s $KEYCLOAK_URL \
  -d "grant_type=refresh_token" \
  -d "client_id=$CLIENT_ID" \
  -d "refresh_token=$REFRESH_TOKEN")
```

## Token Expiration Times

### Keycloak Tokens
```yaml
Access Token:    15 minutes (short-lived)
Refresh Token:   60 minutes (for renewal)
ID Token:        15 minutes
Session:         10 hours max
```

### Application Sessions
```yaml
Session Duration: 24 hours (from creation)
Idle Timeout:     30 minutes (last access)
Cleanup Interval: 5 minutes (background)
```

## Configuration

### Server (config.yaml)
```yaml
server:
  oidc:
    enabled: true
    # Tokens obtained from Keycloak with these settings
    # Server tracks sessions independently
```

### Keycloak Realm Settings
```yaml
Access Token Lifespan: 15 minutes
Refresh Token Max:     1 hour
SSO Session Idle:      30 minutes
SSO Session Max:       10 hours
```

## API Endpoints

### Check Session Status
```bash
curl -b cookies.txt https://localhost:8443/auth/user
```

Response:
```json
{
  "email": "witness1@lottery.org",
  "is_admin": false,
  "is_witness": true,
  "expires_at": "2026-01-22T14:00:00Z",
  "last_accessed": "2026-01-21T14:05:00Z",
  "created_at": "2026-01-21T14:00:00Z"
}
```

### Refresh Session
```bash
curl -X POST -b cookies.txt https://localhost:8443/auth/refresh
```

### Logout
```bash
curl -X POST -b cookies.txt https://localhost:8443/auth/logout
```

## Security Considerations

### Session Storage
- **Current**: In-memory map
- **Limitation**: Lost on server restart
- **Recommendation**: Use Redis or persistent storage for production

### Token Rotation
- **Refresh tokens** should be rotated on each use
- **Access tokens** are short-lived (15 min)
- **Sessions** extend automatically with activity

### Idle Detection
- Sessions auto-expire after 30 minutes idle
- Prevents abandoned sessions from accumulating
- Cleanup runs every 5 minutes

### HTTPS Only
- All tokens transmitted over HTTPS
- Cookies marked `Secure` and `HttpOnly`
- Prevents token theft via XSS or MITM

## Monitoring

### Server Logs

**Session Creation**:
```
INFO Session created
  email=witness1@lottery.org
  session_id=a1b2c3d4...
  expires_at=2026-01-22T14:00:00Z
```

**Session Refresh**:
```
INFO Session refreshed
  email=witness1@lottery.org
  new_expires_at=2026-01-22T15:00:00Z
```

**Cleanup**:
```
DEBUG Removed expired session
  session_id=x9y8z7w6...
  email=olduser@example.com
  expired_at=2026-01-21T12:00:00Z

INFO Session cleanup completed
  initial_count=50
  removed=5
  remaining=45
```

### Metrics to Track

- Active sessions count
- Session creation rate
- Session expiration rate
- Average session duration
- Idle timeout occurrences
- Token refresh frequency

## Future Enhancements

### Planned Features

1. **Automatic Token Refresh in Client**
   - Witness observer tracks token expiry
   - Auto-refreshes before expiration
   - Handles refresh token rotation

2. **Persistent Session Storage**
   - Redis integration
   - Survives server restarts
   - Distributed session sharing

3. **Token Introspection**
   - Query Keycloak for token validity
   - Support for token revocation checks

4. **Graceful Token Renewal**
   - Proactive refresh before expiration
   - Retry logic for failed refreshes
   - Fallback to re-authentication

5. **Session Analytics**
   - Dashboard for active sessions
   - Session history and audit trail
   - Anomaly detection

## Troubleshooting

### "Session expired"
- Session older than 24 hours
- Session idle for >30 minutes
- **Solution**: Call `/auth/refresh` or re-authenticate

### "Token expired" (Watch mode)
- JWT token from Keycloak expired (15 min)
- No auto-refresh in watch mode
- **Solution**: Use workarounds above or use mTLS

### Sessions growing indefinitely
- Cleanup goroutine not running
- **Check**: Server logs for cleanup messages
- **Solution**: Restart server

### Token refresh fails
- Refresh token expired (60 min max)
- Keycloak session ended
- **Solution**: Re-authenticate from scratch

## Examples

### Python Client with Auto-Refresh

```python
import requests
import time
from datetime import datetime, timedelta

class LotteryClient:
    def __init__(self, base_url, keycloak_url, client_id, username, password):
        self.base_url = base_url
        self.keycloak_url = keycloak_url
        self.client_id = client_id
        self.username = username
        self.password = password
        self.token = None
        self.token_expires = None
        self.refresh_token = None
    
    def get_token(self):
        resp = requests.post(self.keycloak_url, data={
            'grant_type': 'password',
            'client_id': self.client_id,
            'username': self.username,
            'password': self.password
        })
        data = resp.json()
        self.token = data['access_token']
        self.refresh_token = data.get('refresh_token')
        self.token_expires = datetime.now() + timedelta(seconds=data['expires_in'])
    
    def refresh_if_needed(self):
        if not self.token or datetime.now() >= self.token_expires - timedelta(minutes=2):
            if self.refresh_token:
                # Use refresh token
                resp = requests.post(self.keycloak_url, data={
                    'grant_type': 'refresh_token',
                    'client_id': self.client_id,
                    'refresh_token': self.refresh_token
                })
                data = resp.json()
                self.token = data['access_token']
                self.refresh_token = data.get('refresh_token', self.refresh_token)
                self.token_expires = datetime.now() + timedelta(seconds=data['expires_in'])
            else:
                # Re-authenticate
                self.get_token()
    
    def observe(self):
        self.refresh_if_needed()
        headers = {'Authorization': f'Bearer {self.token}'}
        resp = requests.post(f'{self.base_url}/api/witness/observe', headers=headers)
        return resp.json()

# Usage
client = LotteryClient(
    'https://localhost:8443',
    'https://keycloak.example.com/realms/lottery/protocol/openid-connect/token',
    'lottery-api',
    'witness1@lottery.org',
    'password'
)

# Watch mode with auto-refresh
while True:
    try:
        result = client.observe()
        print(f"Observed tree: {result}")
    except Exception as e:
        print(f"Error: {e}")
    time.sleep(10)
```

## Summary

The token lifecycle is now properly managed:

✅ **Server-side**: Sessions tracked with expiry and idle timeout  
✅ **Automatic cleanup**: Background goroutine removes stale sessions  
✅ **Session refresh**: Endpoint to extend sessions without re-auth  
✅ **OAuth2 refresh tokens**: Captured and can be used for renewal  
⏳ **Client auto-refresh**: Planned enhancement for witness observer  

For production use, implement:
1. Persistent session storage (Redis)
2. Client-side auto-refresh logic
3. Monitoring and alerting for token issues
