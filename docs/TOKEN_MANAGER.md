# Token Manager - Automatic Token Refresh

The witness observer includes an automatic token manager that handles token lifecycle for long-running operations like watch mode. This eliminates the problem of JWT tokens expiring after 15 minutes.

## Overview

The `TokenManager` is a goroutine-based component that:

1. **Tracks token expiration** - Monitors when the current access token will expire
2. **Automatically refreshes** - Renews tokens 2 minutes before expiration
3. **Uses refresh tokens** - Prefers OAuth2 refresh_token flow when available
4. **Falls back gracefully** - Uses password grant if refresh token fails or unavailable
5. **Thread-safe** - Safe for concurrent access across multiple goroutines
6. **Lifecycle managed** - Automatically starts and can be stopped cleanly

## How It Works

### Token Lifecycle Flow

```
Initial Authentication
         ↓
   Get Access Token (15 min)
   Get Refresh Token (60 min)
         ↓
   Start TokenManager goroutine
         ↓
   Check every 30 seconds
         ↓
   Time until expiry < 2 min?
         ↓
   YES: Refresh token
         ↓
   Try refresh_token grant first
         ↓
   FAIL? Use password_grant
         ↓
   Update access token
   Update refresh token (if provided)
   Reset expiration timer
         ↓
   Continue checking...
```

### Token Manager Architecture

```go
type TokenManager struct {
    accessToken  string        // Current JWT access token
    refreshToken string        // OAuth2 refresh token
    expiresAt    time.Time     // When current token expires
    
    // Authentication credentials
    keycloakURL  string
    clientID     string
    clientSecret string
    username     string
    password     string
    
    // HTTP client for token requests
    httpClient   *http.Client
    
    // Goroutine lifecycle
    ctx          context.Context
    cancel       context.CancelFunc
    
    // Thread safety
    mu           sync.RWMutex
}
```

## Usage

### Automatic Usage (Recommended)

The token manager is **automatically enabled** when using OIDC/Keycloak authentication with the witness observer:

```bash
# Start watch mode with Keycloak authentication
./lottery-tlog witness-observe \
  --witness-id witness1 \
  --server https://lottery-server.example.com \
  --watch \
  --interval 30s \
  --keycloak-url https://keycloak.example.com/realms/lottery/protocol/openid-connect/token \
  --client-id lottery-witness \
  --client-secret secret123 \
  --username witness1@example.com \
  --password password123
```

**Output:**
```
👁️  Starting witness watch mode for: witness1
📡 Monitoring server: https://lottery-server.example.com
⏱️  Check interval: 30s
📋 Last witnessed tree size: 769
🔐 Token manager active - automatic refresh enabled

✅ Watch mode active. Press Ctrl+C to stop.
```

The token manager runs in the background and logs refresh events:

```
INFO Token manager started initial_expires_at=2026-01-21T13:32:15Z refresh_buffer="2 minutes before expiry"
INFO Token expiring soon, initiating refresh expires_at=2026-01-21T13:32:15Z time_until_expiry=1m45s
INFO Token refreshed successfully via refresh_token new_expires_at=2026-01-21T13:47:30Z expires_in=900
```

### Manual Integration

If building custom clients, you can use the token manager directly:

```go
import "lottery-tlog/cmd"

// Get initial tokens
accessToken, refreshToken, expiresIn := authenticateWithKeycloak()

// Create token manager
tokenManager := cmd.NewTokenManager(
    accessToken,
    refreshToken,
    expiresIn,
    keycloakURL,
    clientID,
    clientSecret,
    username,
    password,
    httpClient,
)
defer tokenManager.Stop()

// Use token in requests
for {
    token := tokenManager.GetToken()
    req.Header.Set("Authorization", "Bearer " + token)
    // ... make request
}
```

## Configuration

### Refresh Timing

The token manager uses these defaults:

| Setting | Value | Description |
|---------|-------|-------------|
| Check interval | 30 seconds | How often to check token expiration |
| Refresh buffer | 2 minutes | Refresh this long before expiry |
| Token lifetime | 15 minutes | Default JWT access token duration |
| Refresh token lifetime | 60 minutes | Default OAuth2 refresh token duration |

### Refresh Strategy

1. **Primary: refresh_token grant**
   - Used if Keycloak provided a refresh token
   - More secure (no password transmission)
   - Can rotate refresh tokens
   
2. **Fallback: password grant**
   - Used if refresh_token fails or unavailable
   - Requires username/password credentials
   - Creates new access + refresh tokens

## Token Types

### Access Token (JWT)

- **Purpose:** API authentication
- **Lifetime:** 15 minutes (default)
- **Format:** JWT (JSON Web Token)
- **Usage:** `Authorization: Bearer <access_token>`
- **Refreshable:** Yes (via refresh token)

### Refresh Token (OAuth2)

- **Purpose:** Obtain new access tokens without re-authentication
- **Lifetime:** 60 minutes (default, often longer)
- **Format:** Opaque token (Keycloak-specific)
- **Usage:** Sent to token endpoint to get new access token
- **Refreshable:** Yes (can be rotated)

## Watch Mode Integration

The token manager is especially critical for watch mode, where the witness observer runs indefinitely:

### Before Token Manager

```
Start watch mode → Initial token (15 min)
    ↓
15 minutes pass
    ↓
Token expires
    ↓
❌ All requests fail with 401 Unauthorized
    ↓
Watch mode continues but can't authenticate
```

### With Token Manager

```
Start watch mode → Initial token (15 min)
    ↓
TokenManager goroutine started
    ↓
13 minutes pass (2 min buffer)
    ↓
TokenManager detects expiring soon
    ↓
✅ Automatically refreshes token
    ↓
New token (15 min)
    ↓
Watch mode continues seamlessly
    ↓
(Repeats indefinitely)
```

## Lifecycle Management

### Creation

```go
// Token manager is created automatically when using Keycloak auth
client, token, tokenManager, err := createAuthenticatedClient(...)

// Token manager starts its goroutine immediately
// Logs: "Token manager started initial_expires_at=..."
```

### Running

```go
// Token manager runs in background checking every 30 seconds
// Logs when refresh is needed:
// "Token expiring soon, initiating refresh expires_at=... time_until_expiry=1m45s"

// Logs after successful refresh:
// "Token refreshed successfully via refresh_token new_expires_at=... expires_in=900"
```

### Cleanup

```go
// Token manager is stopped automatically via defer
defer tokenManager.Stop()

// Or manually
tokenManager.Stop()
// Logs: "Token manager stopped"
```

## Thread Safety

The token manager uses `sync.RWMutex` for thread-safe access:

- **GetToken():** Uses read lock (concurrent reads allowed)
- **Refresh operations:** Use write lock (exclusive access)

This allows multiple goroutines to safely call `GetToken()` while the background refresh goroutine updates the token.

## Error Handling

### Refresh Failures

If token refresh fails, the manager logs the error but continues running:

```
WARN Refresh token failed, falling back to password grant error=...
INFO Token refreshed successfully via password_grant new_expires_at=...
```

If both refresh strategies fail:

```
ERROR Token refresh failed error=...
```

The watch mode continues but requests will fail until refresh succeeds.

### Recovery Strategy

1. Try refresh_token grant
2. If fails, try password grant
3. If both fail, log error and retry in 30 seconds
4. User credentials remain in memory for recovery

## Monitoring

### Log Messages

The token manager emits these structured logs:

**Startup:**
```json
{
  "level": "INFO",
  "msg": "Token manager started",
  "initial_expires_at": "2026-01-21T13:32:15Z",
  "refresh_buffer": "2 minutes before expiry"
}
```

**Refresh Initiated:**
```json
{
  "level": "INFO",
  "msg": "Token expiring soon, initiating refresh",
  "expires_at": "2026-01-21T13:32:15Z",
  "time_until_expiry": "1m45s"
}
```

**Refresh Success:**
```json
{
  "level": "INFO",
  "msg": "Token refreshed successfully via refresh_token",
  "new_expires_at": "2026-01-21T13:47:30Z",
  "expires_in": 900
}
```

**Refresh Failure:**
```json
{
  "level": "WARN",
  "msg": "Refresh token failed, falling back to password grant",
  "error": "Keycloak refresh failed (status 400): invalid_grant"
}
```

**Shutdown:**
```json
{
  "level": "INFO",
  "msg": "Token manager stopped"
}
```

### Metrics to Track

Monitor these indicators:

- **Refresh frequency:** Should happen every ~13 minutes (15 min - 2 min buffer)
- **Refresh failures:** Should be rare (0-1% of refreshes)
- **Fallback usage:** Password grant should be infrequent
- **Token lifetime:** Should consistently be 15 minutes after refresh

## Security Considerations

### Credential Storage

The token manager stores credentials in memory:

- ✅ Not persisted to disk
- ✅ Cleared when process exits
- ⚠️ Visible in process memory dumps
- ⚠️ Transmitted in plain text to Keycloak

**Recommendation:** Use refresh tokens instead of storing passwords long-term.

### Token Exposure

- Access tokens are short-lived (15 min)
- Refresh tokens are longer-lived but can be rotated
- Both are transmitted over TLS
- Tokens not logged (only expiry times)

### Refresh Token Rotation

Keycloak can rotate refresh tokens on each use:

```yaml
# Keycloak Realm Settings
refresh-token-rotation: true
```

When enabled, each refresh returns a new refresh token, invalidating the old one. The token manager handles this automatically by updating `tm.refreshToken`.

## Comparison with Server Session Management

### Server-Side (from TOKEN_LIFECYCLE.md)

- **Sessions:** 24 hour absolute expiry, 30 min idle timeout
- **Cleanup:** Background goroutine every 5 minutes
- **Refresh:** POST /auth/refresh endpoint
- **Storage:** In-memory (Redis recommended for production)

### Client-Side (Token Manager)

- **Access tokens:** 15 minute lifetime
- **Check interval:** Every 30 seconds
- **Refresh:** Automatic 2 minutes before expiry
- **Storage:** In-memory only (credentials for recovery)

**Key Difference:** Server manages sessions, client manages tokens. Both work together:

```
Client Token Manager → Fresh JWT → Server Session Validator
                                         ↓
                                   Session active?
                                         ↓
                                   ✅ Request allowed
```

## Troubleshooting

### Token Refresh Not Happening

**Symptom:** Watch mode fails after 15 minutes with 401 errors

**Possible Causes:**
1. Token manager not created (mTLS mode doesn't use token manager)
2. Check interval too long (should be 30 seconds)
3. Refresh buffer too short (should be 2 minutes)

**Solution:**
```bash
# Verify token manager is active
./lottery-tlog witness-observe --watch ... 2>&1 | grep "Token manager"
# Should see: "🔐 Token manager active - automatic refresh enabled"
```

### Refresh Token Invalid

**Symptom:** Logs show "Refresh token failed, falling back to password grant"

**Possible Causes:**
1. Refresh token expired (lifetime exceeded)
2. Refresh token rotation enabled but old token used
3. User session terminated on Keycloak

**Solution:**
- Verify Keycloak refresh token settings
- Check user session is still active
- Token manager will fall back to password grant automatically

### Credentials Invalid

**Symptom:** Both refresh_token and password grants fail

**Possible Causes:**
1. Password changed
2. Account locked/disabled
3. Client secret changed
4. Network connectivity to Keycloak lost

**Solution:**
```bash
# Test credentials manually
curl -X POST https://keycloak.example.com/.../token \
  -d "grant_type=password" \
  -d "client_id=lottery-witness" \
  -d "client_secret=secret123" \
  -d "username=witness1@example.com" \
  -d "password=password123"
```

### Memory Leak in Long-Running Watch Mode

**Symptom:** Memory usage grows over time

**Possible Causes:**
1. Token manager goroutine not stopped
2. Old HTTP clients not garbage collected
3. Log buffer accumulation

**Solution:**
```bash
# Monitor memory usage
watch -n 10 'ps aux | grep lottery-tlog'

# Restart watch mode periodically (systemd service)
[Unit]
Description=Lottery Witness Observer
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/lottery-tlog witness-observe --watch ...
Restart=always
RestartSec=3600  # Restart every hour
```

## Best Practices

### 1. Use Refresh Tokens

Configure Keycloak to issue refresh tokens:

```yaml
# Keycloak Client Settings
access-token-lifespan: 15m
refresh-token-lifespan: 60m
refresh-token-rotation: true
```

### 2. Set Appropriate Buffer Time

The 2-minute buffer prevents race conditions:

- Too short (< 1 min): Risk of requests with expired token
- Too long (> 5 min): Unnecessary token rotations

**Default of 2 minutes is optimal for 15-minute tokens.**

### 3. Monitor Refresh Events

Set up log aggregation to track:

```bash
# Count successful refreshes
grep "Token refreshed successfully" lottery.log | wc -l

# Count failed refreshes
grep "Token refresh failed" lottery.log | wc -l

# Calculate failure rate
```

### 4. Handle Graceful Shutdown

Ensure token manager is stopped cleanly:

```go
// Set up signal handling
sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

go func() {
    <-sigCh
    fmt.Println("\n🛑 Shutting down...")
    tokenManager.Stop()  // Stop token manager
    os.Exit(0)
}()
```

### 5. Secure Credential Handling

For production, avoid passing credentials as flags:

```bash
# Bad: Credentials visible in process list
./lottery-tlog witness-observe --password secret123 ...

# Good: Use environment variables
export LOTTERY_PASSWORD=secret123
./lottery-tlog witness-observe --watch ...
```

Or use Keycloak client credentials with mTLS:

```bash
# Best: Certificate-based authentication
./lottery-tlog witness-observe \
  --witness-id witness1 \
  --server https://lottery-server.example.com \
  --watch \
  --keycloak-url https://keycloak.example.com/.../token \
  --client-id lottery-witness
  # Certificate automatically loaded from witness-cert.pem
```

## Future Enhancements

Potential improvements for the token manager:

### 1. Persistent Token Cache

Store refresh tokens to survive process restarts:

```go
// Save refresh token to encrypted file
tokenManager.SaveToCache("~/.lottery/token-cache.enc")

// Load on startup
tokenManager.LoadFromCache("~/.lottery/token-cache.enc")
```

### 2. Token Introspection

Validate tokens with Keycloak before use:

```go
// Check if token is still valid
isValid := tokenManager.IntrospectToken()
if !isValid {
    tokenManager.ForceRefresh()
}
```

### 3. Multiple Token Managers

Support multiple simultaneous connections:

```go
// One token manager per server connection
tokenManagers := make(map[string]*TokenManager)
tokenManagers[serverURL] = NewTokenManager(...)
```

### 4. Configurable Refresh Strategy

Allow users to tune refresh behavior:

```yaml
token_manager:
  check_interval: 30s
  refresh_buffer: 2m
  prefer_refresh_token: true
  max_retries: 3
  retry_backoff: 10s
```

### 5. Metrics Exporter

Expose Prometheus metrics:

```go
token_refresh_total{result="success"} 145
token_refresh_total{result="failure"} 2
token_refresh_duration_seconds{quantile="0.5"} 0.123
token_ttl_seconds 780
```

## Related Documentation

- [TOKEN_LIFECYCLE.md](TOKEN_LIFECYCLE.md) - Server-side session management
- [KEYCLOAK_MTLS.md](KEYCLOAK_MTLS.md) - Keycloak mTLS configuration
- [WITNESS_KEYCLOAK.md](WITNESS_KEYCLOAK.md) - Witness Keycloak integration
- [OIDC_AUTH.md](OIDC_AUTH.md) - OIDC authentication overview

## Summary

The token manager is a critical component for long-running witness operations:

✅ **Automatic** - No manual intervention required
✅ **Reliable** - Multiple refresh strategies with fallback
✅ **Thread-safe** - Concurrent access supported
✅ **Monitored** - Comprehensive logging for debugging
✅ **Secure** - Credentials in memory only, TLS transport

**For watch mode, the token manager eliminates the 15-minute token expiration problem entirely.**
