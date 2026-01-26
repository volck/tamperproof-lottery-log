# Token Lifecycle - Complete System Overview

This document provides a comprehensive overview of how tokens flow through the entire lottery log system, from client authentication through server validation to automatic refresh.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Keycloak Server                             │
│  • Issues JWT access tokens (15 min)                                │
│  • Issues OAuth2 refresh tokens (60 min)                            │
│  • Can require mTLS for token acquisition                           │
└─────────────────────────────────────────────────────────────────────┘
                                    ▲
                                    │ Token requests
                                    │ (with/without mTLS)
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Client: Token Manager                            │
│  • Monitors token expiration (every 30s)                            │
│  • Refreshes 2 min before expiry                                    │
│  • Uses refresh_token or password grant                             │
│  • Thread-safe token storage                                        │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ API requests with
                                    │ Authorization: Bearer <token>
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Server: Session Manager                           │
│  • Validates JWT tokens                                             │
│  • Creates sessions (24h lifetime)                                  │
│  • Tracks last access (30min idle timeout)                          │
│  • Background cleanup (every 5 min)                                 │
│  • Refresh endpoint (/auth/refresh)                                 │
└─────────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

### Keycloak (Identity Provider)

**Role:** Token issuer and authenticator

**Responsibilities:**
- Authenticate users (username/password, mTLS, etc.)
- Issue JWT access tokens (15 min default)
- Issue OAuth2 refresh tokens (60 min default)
- Validate refresh token requests
- Optionally rotate refresh tokens
- Enforce authentication policies

**Configuration:**
```yaml
# Keycloak Realm Settings
access-token-lifespan: 15m
refresh-token-lifespan: 60m
refresh-token-rotation: true
client-auth: public  # or confidential with client_secret
require-client-cert: false  # Set true for mTLS hybrid
```

### Client Token Manager (witness_observe.go)

**Role:** Client-side token lifecycle management

**Responsibilities:**
- Store current access and refresh tokens
- Monitor token expiration continuously
- Automatically refresh before expiration (2 min buffer)
- Prefer refresh_token grant, fallback to password
- Provide thread-safe token access
- Clean shutdown on process exit

**Key Operations:**
```go
// Initialization
tokenManager := NewTokenManager(accessToken, refreshToken, expiresIn, ...)

// Automatic refresh goroutine
go tokenManager.autoRefresh()  // Checks every 30s

// Thread-safe access
token := tokenManager.GetToken()

// Cleanup
tokenManager.Stop()
```

### Server Session Manager (server/server.go)

**Role:** Server-side session and token validation

**Responsibilities:**
- Validate incoming JWT tokens
- Create application sessions (24h lifetime)
- Track last access time (30min idle timeout)
- Store refresh tokens from OAuth2 flow
- Background cleanup of expired/idle sessions
- Provide refresh endpoint for session extension
- Enforce role-based access (admin, witness)

**Key Operations:**
```go
// Session creation
createSession(email, isAdmin, isWitness, refreshToken)

// Access time tracking
session.LastAccessed = time.Now()

// Background cleanup
go s.sessionCleanupLoop()  // Every 5 minutes

// Session refresh
handleRefreshSession()  // POST /auth/refresh
```

## Token Flow Diagrams

### Initial Authentication Flow

```
┌────────┐                 ┌─────────┐                ┌────────┐
│ Client │                 │Keycloak │                │ Server │
└───┬────┘                 └────┬────┘                └───┬────┘
    │                           │                         │
    │ 1. Token Request          │                         │
    │ (password/mTLS)           │                         │
    ├──────────────────────────>│                         │
    │                           │                         │
    │ 2. Access + Refresh Token │                         │
    │<──────────────────────────┤                         │
    │                           │                         │
    │ 3. Start TokenManager     │                         │
    │    (background goroutine) │                         │
    │                           │                         │
    │ 4. API Request            │                         │
    │ + Authorization: Bearer   │                         │
    ├──────────────────────────────────────────────────>│
    │                           │                         │
    │                           │    5. Validate JWT      │
    │                           │    6. Create Session    │
    │                           │       (store refresh    │
    │                           │        token)           │
    │                           │                         │
    │ 7. Response + Set-Cookie  │                         │
    │<──────────────────────────────────────────────────┤
    │    session_token=xyz      │                         │
    │                           │                         │
```

### Automatic Token Refresh Flow

```
Time: T+13min (2 min before 15min expiry)

┌────────┐                 ┌─────────┐                ┌────────┐
│TokenMgr│                 │Keycloak │                │ Server │
└───┬────┘                 └────┬────┘                └───┬────┘
    │                           │                         │
    │ Check expiration          │                         │
    │ (every 30 seconds)        │                         │
    │                           │                         │
    │ Time until expiry: 1m45s  │                         │
    │ → Trigger refresh         │                         │
    │                           │                         │
    │ 1. Refresh Token Request  │                         │
    │ (grant_type=refresh_token)│                         │
    ├──────────────────────────>│                         │
    │                           │                         │
    │ 2. New Access + Refresh   │                         │
    │    Token (15 min)         │                         │
    │<──────────────────────────┤                         │
    │                           │                         │
    │ 3. Update internal tokens │                         │
    │    tm.accessToken = new   │                         │
    │    tm.refreshToken = new  │                         │
    │    tm.expiresAt = T+15min │                         │
    │                           │                         │
    │ 4. Continue API requests  │                         │
    │    with new token         │                         │
    ├──────────────────────────────────────────────────>│
    │                           │                         │
    │                           │    5. Validate new JWT  │
    │                           │    6. Update session    │
    │                           │       LastAccessed      │
    │                           │                         │
    │ 7. Response               │                         │
    │<──────────────────────────────────────────────────┤
    │                           │                         │
    │ Continue for another 13min│                         │
    │ then refresh again...     │                         │
    │                           │                         │
```

### Session Refresh Flow (Alternative)

```
When client wants to extend session without OAuth2 refresh:

┌────────┐                                              ┌────────┐
│ Client │                                              │ Server │
└───┬────┘                                              └───┬────┘
    │                                                       │
    │ POST /auth/refresh                                    │
    │ Cookie: session_token=xyz                             │
    ├──────────────────────────────────────────────────────>│
    │                                                       │
    │                                  1. Lookup session    │
    │                                  2. Check if valid    │
    │                                  3. Check refresh     │
    │                                     token exists      │
    │                                                       │
    │                                  4. Use OAuth2        │
    │                                     refresh token     │
    │                                     to get new        │
    │                                     access token      │
    │                                     from Keycloak     │
    │                                                       │
    │                                  5. Update session:   │
    │                                     - ExpiresAt +24h  │
    │                                     - LastAccessed    │
    │                                     - RefreshToken    │
    │                                                       │
    │ 200 OK                                                │
    │ {session_id, expires_at, last_accessed}               │
    │<──────────────────────────────────────────────────────┤
    │                                                       │
```

## Token Expiration Timeline

### Client Perspective (Watch Mode)

```
T+0:00   │ Initial auth → Access token (15m), Refresh token (60m)
         │ TokenManager started
         │
T+0:30   │ First check (token OK, 14m30s remaining)
T+1:00   │ Check (token OK, 14m remaining)
...
T+13:00  │ Check (token OK, 2m remaining)
T+13:30  │ Check → REFRESH TRIGGERED (1m30s remaining < 2m buffer)
         │ ┌──────────────────────────────────────────┐
         │ │ 1. Request: refresh_token grant          │
         │ │ 2. Receive: New access token (15m)       │
         │ │ 3. Update: tm.accessToken, tm.expiresAt  │
         │ │ 4. Log: "Token refreshed successfully"   │
         │ └──────────────────────────────────────────┘
         │
T+13:30  │ New token active (15m = T+28:30 expiry)
T+14:00  │ Check (token OK, 14m30s remaining)
...
T+26:30  │ Check (token OK, 2m remaining)
T+27:00  │ Check → REFRESH TRIGGERED again
         │ (Cycle repeats)
```

### Server Perspective (Same Client)

```
T+0:00   │ JWT received → Valid → Session created
         │ Session: {Email, CreatedAt: T+0:00, ExpiresAt: T+24:00, LastAccessed: T+0:00}
         │
T+0:05   │ API request → Update LastAccessed: T+0:05
T+0:10   │ API request → Update LastAccessed: T+0:10
...
T+13:30  │ API request with REFRESHED token → Update LastAccessed: T+13:30
         │ (New JWT but same session)
...
T+5:00   │ Background cleanup runs (every 5 min)
         │ ┌──────────────────────────────────────────┐
         │ │ For each session:                        │
         │ │   - Expired? (ExpiresAt < now)           │
         │ │   - Idle? (LastAccessed + 30m < now)     │
         │ │   If yes → Delete session                │
         │ └──────────────────────────────────────────┘
         │
T+24:00  │ Session expires (absolute 24h limit)
         │ Next cleanup cycle will delete it
         │
OR       │
         │
T+X+30m  │ If no activity for 30 minutes
         │ Session deleted as idle
```

## Configuration Summary

### Keycloak Token Configuration

```yaml
# /realms/{realm-name}/token-settings
access_token_lifespan: 15m       # How long JWT is valid
refresh_token_lifespan: 60m      # How long refresh token valid
refresh_token_rotation: true     # Issue new refresh token on use
client_authentication: public    # or confidential with secret
```

### Client Token Manager Settings

```go
// cmd/witness_observe.go
const (
    CheckInterval  = 30 * time.Second  // How often to check expiration
    RefreshBuffer  = 2 * time.Minute   // Refresh this early before expiry
)

// Token manager behavior
- Checks every 30 seconds
- Refreshes when: time.Until(expiresAt) < 2 minutes
- Refresh strategy:
  1. Try refresh_token grant
  2. If fails, try password grant
  3. If both fail, log error and retry next cycle
```

### Server Session Settings

```go
// server/server.go
const (
    SessionLifetime       = 24 * time.Hour  // Absolute session expiry
    SessionIdleTimeout    = 30 * time.Minute // Idle timeout
    CleanupInterval       = 5 * time.Minute  // Cleanup frequency
)

// Session behavior
- Created on first valid JWT
- Updated LastAccessed on every request
- Expires after 24 hours (absolute)
- Expires after 30 minutes idle
- Cleanup runs every 5 minutes
```

## Integration Points

### 1. Client ↔ Keycloak

**Protocol:** OAuth2 Password Grant / Refresh Token Grant

**Endpoints:**
- `POST /realms/{realm}/protocol/openid-connect/token`

**Flows:**
- Initial: `grant_type=password` + username/password
- Refresh: `grant_type=refresh_token` + refresh_token

**Authentication:**
- Optional: mTLS (client certificate)
- Required: client_id + client_secret (if confidential client)

### 2. Client ↔ Server

**Protocol:** HTTPS with JWT Bearer authentication

**Endpoints:**
- `POST /api/witness/observe` - Get current tree state
- `POST /api/witness/heartbeat` - Keep-alive signal
- `GET /api/draws/since/{size}` - Get new draws
- `POST /auth/refresh` - Refresh session

**Authentication:**
- Primary: `Authorization: Bearer <jwt>`
- Fallback: mTLS (client certificate)
- Session: `Cookie: session_token=<uuid>`

### 3. Server ↔ Keycloak

**Protocol:** OIDC (OpenID Connect)

**Operations:**
- JWT validation (via OIDC discovery)
- User info retrieval (optional)
- Token introspection (optional)
- Refresh token usage (for session refresh)

**Configuration:**
```yaml
# config.yaml
oidc:
  issuer_url: "https://keycloak.example.com/realms/lottery"
  client_id: "lottery-server"
  client_secret: "server-secret-123"
  redirect_url: "https://lottery-server.example.com/auth/callback"
```

## Monitoring and Observability

### Client-Side Metrics

**Token Manager Events:**
```
Token manager started
Token expiring soon, initiating refresh
Token refreshed successfully via refresh_token
Refresh token failed, falling back to password grant
Token refresh failed
Token manager stopped
```

**Watch for:**
- Refresh failures (should be < 1%)
- Fallback to password grant (indicates refresh token issues)
- Time until expiry when refresh triggered (should be ~2 minutes)

### Server-Side Metrics

**Session Events:**
```
Session created
Session refreshed
Session deleted
Expired sessions cleaned
Idle sessions cleaned
```

**Watch for:**
- Session creation rate (= authentication rate)
- Session expiry rate (should match creation rate ± idle timeouts)
- Cleanup efficiency (expired/idle found each cycle)

### End-to-End Health Check

```bash
#!/bin/bash
# Token lifecycle health check

# 1. Get token from Keycloak
TOKEN=$(curl -s -X POST "$KEYCLOAK_URL" \
  -d "grant_type=password&client_id=$CLIENT_ID&username=$USERNAME&password=$PASSWORD" \
  | jq -r '.access_token')

# 2. Use token with server
curl -H "Authorization: Bearer $TOKEN" "$SERVER_URL/api/witness/observe"

# 3. Check token expiry
echo "$TOKEN" | jwt decode - | jq '.exp'

# 4. Verify session exists on server
curl -b "session_token=$SESSION_ID" "$SERVER_URL/api/auth/user"

# 5. Test refresh
curl -X POST -b "session_token=$SESSION_ID" "$SERVER_URL/auth/refresh"
```

## Troubleshooting Matrix

| Symptom | Client Issue | Server Issue | Keycloak Issue |
|---------|-------------|--------------|----------------|
| 401 after 15 min | TokenManager not running | Session expired | Token expired |
| Continuous 401s | Wrong credentials | OIDC config wrong | Client not registered |
| Refresh failures | Network to Keycloak | - | Refresh token expired |
| Session not created | - | JWT validation failed | Token format wrong |
| Session expires early | - | Idle timeout too short | Access token too short |
| Memory leak | TokenManager not stopped | Session cleanup not running | - |

### Debug Commands

**Check client token:**
```bash
# View JWT contents
echo "$ACCESS_TOKEN" | jwt decode -

# Check expiry
echo "$ACCESS_TOKEN" | jwt decode - | jq -r '.exp | tonumber | strftime("%Y-%m-%d %H:%M:%S")'
```

**Check server session:**
```bash
# View session info
curl -b "session_token=$SESSION_ID" https://server/api/auth/user

# Force refresh
curl -X POST -b "session_token=$SESSION_ID" https://server/auth/refresh
```

**Check Keycloak:**
```bash
# Introspect token
curl -X POST "$KEYCLOAK_URL/introspect" \
  -d "token=$ACCESS_TOKEN" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET"
```

## Security Considerations

### Token Storage

| Location | Access Token | Refresh Token | Session ID |
|----------|--------------|---------------|------------|
| Client memory | ✅ Yes | ✅ Yes | ✅ Yes (cookie) |
| Client disk | ❌ No | ⚠️ Optional (encrypted) | ❌ No |
| Server memory | ❌ No (stateless JWT) | ✅ Yes (in session) | ✅ Yes |
| Server disk | ❌ No | ⚠️ Optional (Redis) | ⚠️ Optional (Redis) |

### Credential Transmission

- **Password:** Only sent to Keycloak, not to server
- **Client Secret:** Only sent to Keycloak
- **Access Token:** Sent to server on every request
- **Refresh Token:** Only sent to Keycloak for refresh
- **Session ID:** Sent to server via HTTP-only cookie

### Attack Mitigation

**Token Theft:**
- Short access token lifetime (15 min)
- Refresh token rotation
- HTTP-only cookies for session
- TLS for all communication

**Session Hijacking:**
- Secure cookies (HTTPS only)
- Idle timeout (30 min)
- Absolute timeout (24h)
- IP binding (optional)

**Credential Exposure:**
- Credentials not logged
- Cleared from memory on shutdown
- Environment variables preferred over CLI args

## Production Recommendations

### Client Deployment

1. **Use systemd for watch mode:**
```ini
[Service]
ExecStart=/usr/local/bin/lottery-tlog witness-observe --watch ...
Restart=always
RestartSec=30
```

2. **Use environment variables:**
```bash
export LOTTERY_KEYCLOAK_URL=...
export LOTTERY_CLIENT_SECRET=...
export LOTTERY_PASSWORD=...
```

3. **Enable structured logging:**
```bash
./lottery-tlog --log-format json witness-observe ...
```

### Server Deployment

1. **Use Redis for sessions:**
```go
// Replace in-memory sessions with Redis
store := redistore.NewRediStore(10, "tcp", "localhost:6379", "", []byte("secret"))
```

2. **Configure session timeouts:**
```yaml
# config.yaml
sessions:
  lifetime: 24h
  idle_timeout: 30m
  cleanup_interval: 5m
```

3. **Enable Prometheus metrics:**
```go
// Expose session metrics
prometheus.Register(sessionGauge)
prometheus.Register(refreshCounter)
```

### Keycloak Configuration

1. **Set appropriate token lifetimes:**
   - Access: 15 minutes (balance security vs refresh frequency)
   - Refresh: 60 minutes (allows 4 refreshes per hour)

2. **Enable refresh token rotation:**
   - Improves security
   - Automatically handled by TokenManager

3. **Configure session policies:**
   - SSO session idle: 30 minutes
   - SSO session max: 24 hours
   - Client session idle: 30 minutes

## Summary

The complete token lifecycle involves three components working together:

1. **TokenManager (Client):** Automatic token refresh every ~13 minutes
2. **SessionManager (Server):** Long-lived sessions (24h) with idle timeout (30m)
3. **Keycloak (IdP):** Token issuer with configurable lifetimes

**Key Benefits:**
- ✅ Seamless authentication for long-running processes
- ✅ Short-lived tokens for security
- ✅ Automatic refresh without user intervention
- ✅ Multiple layers of timeout protection
- ✅ Comprehensive monitoring and debugging

**For watch mode specifically:**
- Client token refreshes every 13 minutes (automatic)
- Server session lasts 24 hours (or 30 min idle)
- No manual re-authentication required
- Continues indefinitely with proper monitoring

## Related Documentation

- [TOKEN_MANAGER.md](TOKEN_MANAGER.md) - Client token manager details
- [TOKEN_LIFECYCLE.md](TOKEN_LIFECYCLE.md) - Server session management
- [KEYCLOAK_MTLS.md](KEYCLOAK_MTLS.md) - Keycloak mTLS hybrid
- [OIDC_AUTH.md](OIDC_AUTH.md) - OIDC authentication setup
