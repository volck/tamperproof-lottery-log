# Keycloak mTLS Testing Environment

This directory contains everything needed to test mTLS authentication with Keycloak for the lottery log system, including a complete Docker-based test environment with both Keycloak and the lottery-tlog server.

## Quick Start

```bash
# Easy way: Use the management script
./manage.sh setup    # Generates certs and starts everything
./manage.sh status   # Check if services are ready
./manage.sh test     # Run authentication tests

# Manual way:
# 1. Generate test certificates
./generate-certs.sh

# 2. Start both Keycloak and lottery-tlog server
docker-compose up -d

# 3. Wait for services to be ready (30-60 seconds)
docker-compose logs -f

# Watch for:
# - keycloak: "Keycloak 23.0... started"
# - lottery-tlog: "Server listening on https://0.0.0.0:8443"

# 4. Run authentication tests
./test-auth.sh

# 5. Test with witness observer (from host machine)
cd ..
./lottery-tlog witness-observe \
  --witness-id witness1 \
  --server https://localhost:8080 \
  --keycloak-url https://localhost:8443/realms/lottery/protocol/openid-connect/token \
  --client-id lottery-witness \
  --username witness1@example.com \
  --password password123 \
  --watch
```

## Management Script

The `manage.sh` script provides convenient commands for managing the test environment:

```bash
./manage.sh setup       # Generate certificates and start services
./manage.sh start       # Start all services
./manage.sh stop        # Stop all services
./manage.sh status      # Show service status and health
./manage.sh logs        # Show logs from all services
./manage.sh test        # Run authentication tests
./manage.sh rebuild     # Rebuild Docker images
./manage.sh clean       # Remove everything (containers, volumes, data)
./manage.sh help        # Show all available commands
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Docker Network: lottery-test-network                   │
│                                                          │
│  ┌──────────────────┐         ┌──────────────────┐     │
│  │   Keycloak       │         │  lottery-tlog    │     │
│  │   Port: 8443     │◄────────┤  Port: 8443      │     │
│  │   (HTTPS+mTLS)   │  OIDC   │  (HTTPS)         │     │
│  └──────────────────┘         └──────────────────┘     │
│         │                              │                │
└─────────┼──────────────────────────────┼────────────────┘
          │                              │
          │ Host Port: 8443              │ Host Port: 8080
          ▼                              ▼
    ┌──────────────────────────────────────────┐
    │        Host Machine                      │
    │  • Witness Observer CLI                  │
    │  • curl testing                          │
    │  • Browser (admin console)               │
    └──────────────────────────────────────────┘
```

## What Gets Created

### Docker Services

1. **keycloak** - Identity provider
   - Port 8443 (mapped to host 8443)
   - Admin console: https://localhost:8443/admin
   - Auto-imports lottery realm
   - mTLS enabled (optional client certs)

2. **lottery-tlog** - Lottery transparency log server
   - Port 8443 (mapped to host 8080)
   - API: https://localhost:8080/api/*
   - OIDC authentication via Keycloak
   - Persistent data volume

### Certificates (via `generate-certs.sh`)

```
test-mtls/
├── ca/
│   ├── ca-cert.pem              # Certificate Authority
│   └── ca-key.pem
├── server/
│   ├── keycloak-cert.pem        # Server certificate (shared)
│   ├── keycloak-key.pem
│   ├── keycloak-keystore.p12    # PKCS12 keystore (for Keycloak)
│   └── keycloak-truststore.jks  # Truststore with CA cert
└── client/
    ├── witness1-cert.pem        # Client certificates
    ├── witness1-key.pem
    ├── witness1-combined.pem    # Cert + key in one file
    ├── witness1.p12             # PKCS12 (for browsers)
    ├── witness2-cert.pem
    ├── witness2-key.pem
    ├── witness2-combined.pem
    ├── witness2.p12
    ├── admin1-cert.pem
    ├── admin1-key.pem
    ├── admin1-combined.pem
    └── admin1.p12
```
    ├── witness2-key.pem
    ├── witness2-combined.pem
    ├── witness2.p12
    ├── admin1-cert.pem
    ├── admin1-key.pem
    ├── admin1-combined.pem
    └── admin1.p12
```

### Keycloak Configuration

- **Realm:** `lottery`
- **Admin:** admin / admin
- **Token Endpoint:** `https://localhost:8443/realms/lottery/protocol/openid-connect/token`
- **Admin Console:** `https://localhost:8443/admin`

### Test Users

| Username | Password | Roles | Certificate |
|----------|----------|-------|-------------|
| witness1@example.com | password123 | witness, user | client/witness1-combined.pem |
| witness2@example.com | password123 | witness, user | client/witness2-combined.pem |
| admin1@example.com | admin123 | admin, user | client/admin1-combined.pem |

### Clients

| Client ID | Type | Description |
|-----------|------|-------------|
| lottery-witness | Public | For witness observers (direct access grants) |
| lottery-server | Confidential | For server OIDC flow (secret: server-secret-change-in-production) |

## Authentication Modes

### Mode 1: Password Grant (No mTLS)

Basic OAuth2 password grant without client certificate:

```bash
curl --cacert ca/ca-cert.pem \
  -X POST https://localhost:8443/realms/lottery/protocol/openid-connect/token \
  -d "grant_type=password" \
  -d "client_id=lottery-witness" \
  -d "username=witness1@example.com" \
  -d "password=password123"
```

### Mode 2: Password Grant with mTLS

OAuth2 password grant with client certificate (hybrid approach):

```bash
curl --cacert ca/ca-cert.pem \
  --cert client/witness1-combined.pem \
  -X POST https://localhost:8443/realms/lottery/protocol/openid-connect/token \
  -d "grant_type=password" \
  -d "client_id=lottery-witness" \
  -d "username=witness1@example.com" \
  -d "password=password123"
```

The client certificate is validated and may be included in JWT claims.

### Mode 3: Refresh Token Grant

Use refresh token to get new access token:

```bash
curl --cacert ca/ca-cert.pem \
  -X POST https://localhost:8443/realms/lottery/protocol/openid-connect/token \
  -d "grant_type=refresh_token" \
  -d "client_id=lottery-witness" \
  -d "refresh_token=$REFRESH_TOKEN"
```

## Testing Scenarios

### Test 1: Basic Authentication

```bash
./test-auth.sh
```

This runs 6 test scenarios:
1. ✅ Password grant without client cert
2. ✅ Password grant with client cert
3. ✅ Refresh token grant
4. ✅ Different user with matching cert
5. ✅ Admin user authentication
6. ✅ Invalid credentials (should fail)

### Test 2: Witness Observer Integration

```bash
# Start the lottery server first (in separate terminal)
cd ..
./lottery-tlog server-init
./lottery-tlog server

# In another terminal, test witness observer with Keycloak
cd test-mtls
../lottery-tlog witness-observe \
  --witness-id witness1 \
  --server https://localhost:8080 \
  --keycloak-url https://localhost:8443/realms/lottery/protocol/openid-connect/token \
  --client-id lottery-witness \
  --username witness1@example.com \
  --password password123 \
  --watch \
  --interval 30s
```

Expected output:
```
👁️  Starting witness watch mode for: witness1
📡 Monitoring server: https://localhost:8080
⏱️  Check interval: 30s
🔐 Token manager active - automatic refresh enabled

✅ Watch mode active. Press Ctrl+C to stop.
```

### Test 3: Token Lifecycle

Watch token automatic refresh in action:

```bash
# Enable debug logging
export LOG_LEVEL=debug

# Start watch mode
../lottery-tlog witness-observe \
  --witness-id witness1 \
  --server https://localhost:8080 \
  --keycloak-url https://localhost:8443/realms/lottery/protocol/openid-connect/token \
  --client-id lottery-witness \
  --username witness1@example.com \
  --password password123 \
  --watch

# Watch for these log messages:
# INFO Token manager started initial_expires_at=...
# INFO Token expiring soon, initiating refresh (after ~13 minutes)
# INFO Token refreshed successfully via refresh_token
```

### Test 4: Browser Testing

1. Import CA certificate in browser:
   - Chrome: Settings → Privacy → Manage certificates → Authorities → Import `ca/ca-cert.pem`
   - Firefox: Preferences → Privacy → Certificates → View Certificates → Authorities → Import

2. Import client certificate:
   - Chrome: Settings → Privacy → Manage certificates → Your Certificates → Import `client/witness1.p12`
   - Firefox: Preferences → Privacy → Certificates → View Certificates → Your Certificates → Import
   - Password: `changeit`

3. Access Keycloak admin console:
   - URL: https://localhost:8443/admin
   - Browser will prompt for certificate (select witness1 or admin1)
   - Login with admin/admin

## Configuration Details

### Keycloak Settings

**Token Lifetimes:**
```json
{
  "accessTokenLifespan": 900,          // 15 minutes
  "accessTokenLifespanForImplicitFlow": 900,
  "ssoSessionIdleTimeout": 1800,       // 30 minutes
  "ssoSessionMaxLifespan": 86400,      // 24 hours
  "refreshTokenMaxReuse": 0            // No reuse limit
}
```

**mTLS Configuration:**
- `KC_HTTPS_CLIENT_AUTH: request` - Optional client certificate
- `KC_HTTPS_TRUST_STORE_FILE` - Points to truststore with CA cert
- Client certificates are validated against the CA

**Authentication Flow:**
- Cookie-based SSO
- X.509 certificate (optional)
- Username/password form (fallback)

### Docker Compose Options

**Development Mode (default):**
```bash
docker-compose up -d
```
- Uses embedded H2 database (data lost on restart)
- Auto-imports realm configuration
- Health checks enabled
- Ports: 8443 (HTTPS), 9000 (health/metrics)

**Production Mode (with PostgreSQL):**
```bash
docker-compose --profile production up -d
```
- Uses PostgreSQL for persistent storage
- Data survives container restarts
- Additional port: 5432 (PostgreSQL)

## Troubleshooting

### Keycloak Not Starting

**Symptom:** Container exits or health check fails

**Check logs:**
```bash
docker-compose logs keycloak
```

**Common issues:**
- Certificate files not found → Run `./generate-certs.sh`
- Port 8443 already in use → Change port in docker-compose.yml
- Insufficient memory → Increase Docker memory limit

### Certificate Errors

**Symptom:** `SSL certificate problem: unable to get local issuer certificate`

**Solution:**
```bash
# Always use --cacert to trust the test CA
curl --cacert ca/ca-cert.pem ...

# Or ignore certificate validation (testing only!)
curl -k ...
```

### Authentication Failures

**Symptom:** `invalid_grant` or `unauthorized_client`

**Check:**
1. User exists: https://localhost:8443/admin → Users
2. Client configuration: Realms → lottery → Clients → lottery-witness
3. Direct access grants enabled
4. Credentials are correct

**Reset user password:**
```bash
# Via admin console
https://localhost:8443/admin → Users → witness1 → Credentials → Reset Password
```

### Token Manager Not Refreshing

**Symptom:** Requests fail after 15 minutes

**Check:**
1. Token manager is active: Look for "🔐 Token manager active" message
2. Keycloak is accessible: `curl -k https://localhost:8443/health/ready`
3. Refresh token was received: Check initial authentication response
4. Logs show refresh attempts: Look for "Token expiring soon" messages

**Manual refresh test:**
```bash
# Get initial tokens
RESPONSE=$(curl -s --cacert ca/ca-cert.pem \
  -X POST https://localhost:8443/realms/lottery/protocol/openid-connect/token \
  -d "grant_type=password" \
  -d "client_id=lottery-witness" \
  -d "username=witness1@example.com" \
  -d "password=password123")

REFRESH_TOKEN=$(echo $RESPONSE | jq -r '.refresh_token')

# Wait 1 minute, then try refresh
sleep 60

curl -s --cacert ca/ca-cert.pem \
  -X POST https://localhost:8443/realms/lottery/protocol/openid-connect/token \
  -d "grant_type=refresh_token" \
  -d "client_id=lottery-witness" \
  -d "refresh_token=$REFRESH_TOKEN" | jq
```

## Cleanup

```bash
# Stop Keycloak
docker-compose down

# Remove all containers and volumes
docker-compose down -v

# Remove generated certificates
rm -rf ca/ server/ client/ certs/

# Remove Docker images
docker rmi quay.io/keycloak/keycloak:23.0 postgres:15-alpine
```

## Security Notes

⚠️ **THIS IS A TEST ENVIRONMENT ONLY!**

**Do NOT use in production:**
- Self-signed certificates
- Weak passwords (password123, admin123)
- Public client (no client secret required)
- Unencrypted private keys
- Permissive CORS settings
- Development mode Keycloak

**For production:**
1. Use certificates from trusted CA
2. Strong passwords and secrets
3. Confidential clients with secrets
4. Encrypted private keys
5. Proper CORS configuration
6. Production-mode Keycloak with external database
7. Enable all security features (OCSP, CRL, etc.)

## References

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [X.509 Client Certificate Authentication](https://www.keycloak.org/docs/latest/server_admin/#_x509)
- [OAuth2 Password Grant](https://oauth.net/2/grant-types/password/)
- [TOKEN_COMPLETE.md](../docs/TOKEN_COMPLETE.md) - Complete token lifecycle
- [KEYCLOAK_MTLS.md](../docs/KEYCLOAK_MTLS.md) - Keycloak mTLS configuration guide

## Support

For issues or questions:
1. Check logs: `docker-compose logs keycloak`
2. Review Keycloak admin console: https://localhost:8443/admin
3. Test authentication: `./test-auth.sh`
4. Check documentation in `docs/` directory
