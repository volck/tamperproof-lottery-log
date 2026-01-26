# Quick Start Guide - Complete Test Environment

This guide will get you up and running with the complete lottery log system including Keycloak authentication and the lottery-tlog server.

## 1. Setup (First Time Only)

```bash
cd test-mtls
./manage.sh setup
```

This will:
- Generate all required certificates (CA, server, client)
- Build the Docker images
- Start both Keycloak and lottery-tlog server
- Wait for services to be ready

Expected output:
```
🔧 Setting up test environment...
📋 Generating certificates...
🏗️  Building and starting services...
✅ Setup complete!
```

## 2. Verify Services are Running

```bash
./manage.sh status
```

You should see:
```
📊 Service Status
====================
NAME                    STATUS     PORTS
lottery-keycloak-test   running    0.0.0.0:8443->8443/tcp, 0.0.0.0:9000->9000/tcp
lottery-tlog-server     running    0.0.0.0:8080->8443/tcp

Keycloak Health:
  ✅ Ready
Lottery-tlog Health:
  ✅ Ready
```

## 3. Run Authentication Tests

```bash
./manage.sh test
```

This runs 6 test scenarios:
1. ✅ Password grant without client certificate
2. ✅ Password grant with client certificate
3. ✅ Refresh token grant
4. ✅ Different user with matching certificate
5. ✅ Admin user authentication
6. ✅ Invalid credentials (should fail)

## 4. Test Witness Observer

From the main directory:

```bash
cd ..

# Single observation
./lottery-tlog witness-observe \
  --witness-id witness1 \
  --server https://localhost:8080 \
  --keycloak-url https://localhost:8443/realms/lottery/protocol/openid-connect/token \
  --client-id lottery-witness \
  --username witness1@example.com \
  --password password123

# Watch mode (continuous monitoring with automatic token refresh)
./lottery-tlog witness-observe \
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

## 5. Add Test Data

```bash
cd test-mtls
./manage.sh add-draw
```

Or manually using curl:

```bash
# Get a token
TOKEN=$(curl -s --cacert test-mtls/ca/ca-cert.pem \
  -X POST https://localhost:8443/realms/lottery/protocol/openid-connect/token \
  -d "grant_type=password" \
  -d "client_id=lottery-witness" \
  -d "username=admin1@example.com" \
  -d "password=admin123" | jq -r '.access_token')

# Add a draw
curl -k -X POST https://localhost:8080/api/draws \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "seq_no": 1,
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.000Z)'",
    "message": {
      "code": 300,
      "text": "Test lottery draw",
      "game_properties": {
        "game": 1,
        "draw": 1,
        "subdraw": 0
      }
    }
  }'
```

## 6. Access Admin Consoles

### Keycloak Admin Console
- URL: https://localhost:8443/admin
- Username: admin
- Password: admin

### View Lottery Log Status
```bash
curl -k https://localhost:8080/api/status | jq
```

## Common Operations

### View Logs
```bash
cd test-mtls

# All services
./manage.sh logs

# Just Keycloak
./manage.sh logs-keycloak

# Just lottery-tlog
./manage.sh logs-tlog
```

### Restart Services
```bash
./manage.sh restart
```

### Stop Everything
```bash
./manage.sh stop
```

### Start Services (after stopping)
```bash
./manage.sh start
```

### Complete Cleanup (removes all data)
```bash
./manage.sh clean
```

## Troubleshooting

### Services not starting
```bash
# Check logs
cd test-mtls
docker-compose logs

# Check specific service
docker-compose logs keycloak
docker-compose logs lottery-tlog
```

### Certificate errors
```bash
# Regenerate certificates
cd test-mtls
rm -rf ca/ server/ client/ certs/
./generate-certs.sh

# Restart services
./manage.sh restart
```

### Port conflicts
If ports 8080 or 8443 are already in use, edit `docker-compose.yml`:

```yaml
ports:
  - "9443:8443"  # Change 8443 to 9443
  - "9080:8443"  # Change 8080 to 9080
```

### Token not refreshing
Check that:
1. Token manager is active (look for "🔐 Token manager active" message)
2. Keycloak is accessible from within the container
3. Refresh tokens are being issued by Keycloak

Enable debug logging:
```bash
cd ..
LOG_LEVEL=debug ./lottery-tlog witness-observe --watch ...
```

## Test Credentials

### Users
| Username | Password | Role | Use Case |
|----------|----------|------|----------|
| witness1@example.com | password123 | witness | Observing lottery draws |
| witness2@example.com | password123 | witness | Multiple witness testing |
| admin1@example.com | admin123 | admin | Adding draws, admin operations |

### Keycloak Admin
- Username: admin
- Password: admin

### Client Certificates
- witness1: `test-mtls/client/witness1-combined.pem`
- witness2: `test-mtls/client/witness2-combined.pem`
- admin1: `test-mtls/client/admin1-combined.pem`

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Host Machine (localhost)                       │
│                                                  │
│  Port 8443: Keycloak                            │
│  Port 8080: Lottery-tlog Server                 │
│                                                  │
│  ┌──────────────────────────────────────┐       │
│  │  Docker Network                      │       │
│  │                                      │       │
│  │  ┌────────────┐    ┌──────────────┐ │       │
│  │  │ Keycloak   │◄───│ lottery-tlog │ │       │
│  │  │ :8443      │OIDC│ :8443        │ │       │
│  │  └────────────┘    └──────────────┘ │       │
│  │                                      │       │
│  └──────────────────────────────────────┘       │
│                                                  │
│  ┌──────────────────────────────────────┐       │
│  │  Witness Observer (native binary)    │       │
│  │  • Authenticates via Keycloak        │       │
│  │  • Connects to lottery-tlog server   │       │
│  │  • Token manager handles refresh     │       │
│  └──────────────────────────────────────┘       │
│                                                  │
└─────────────────────────────────────────────────┘
```

## Next Steps

1. **Test Token Lifecycle**: Run watch mode for 15+ minutes to see automatic token refresh
2. **Test Multiple Witnesses**: Run multiple witness observers simultaneously
3. **Test Browser Access**: Import client certificates and access admin console
4. **Production Deployment**: Review security considerations in main documentation

## Related Documentation

- [test-mtls/README.md](README.md) - Detailed testing documentation
- [../docs/TOKEN_MANAGER.md](../docs/TOKEN_MANAGER.md) - Token manager details
- [../docs/TOKEN_COMPLETE.md](../docs/TOKEN_COMPLETE.md) - Complete token lifecycle
- [../docs/KEYCLOAK_MTLS.md](../docs/KEYCLOAK_MTLS.md) - Keycloak mTLS configuration

## Support

For issues:
1. Check service status: `./manage.sh status`
2. View logs: `./manage.sh logs`
3. Run tests: `./manage.sh test`
4. Review documentation in `docs/` directory
