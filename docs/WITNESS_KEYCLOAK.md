# Witness Observer with Keycloak Authentication

The witness observer now supports **both mTLS and OIDC/Keycloak authentication** out of the box.

## Usage Options

### Option 1: Direct mTLS (Original Method)

Uses client certificates directly to authenticate with the lottery API server.

```bash
./lottery-tlog witness-observe \
  --witness-id "witness1" \
  --server "https://localhost:8443"
```

**Prerequisites:**
- Witness certificate generated with `witness-init`
- Server configured with `auth_method: "mtls"`

### Option 2: Keycloak with mTLS (Hybrid)

Authenticates to Keycloak using mTLS, receives JWT token, then uses JWT for API calls.

```bash
./lottery-tlog witness-observe \
  --witness-id "witness1" \
  --server "https://localhost:8443" \
  --keycloak-url "https://keycloak.example.com/realms/lottery/protocol/openid-connect/token" \
  --client-id "lottery-api" \
  --client-secret "your-client-secret" \
  --username "witness1@lottery.org" \
  --password "witness-password"
```

**Prerequisites:**
- Witness certificate for Keycloak authentication
- Keycloak configured for X.509 authentication
- Server configured with `auth_method: "oidc"`

### Option 3: Keycloak Password Grant (No Certificates)

Pure OIDC authentication without certificates.

```bash
./lottery-tlog witness-observe \
  --witness-id "witness1" \
  --server "https://localhost:8443" \
  --keycloak-url "https://keycloak.example.com/realms/lottery/protocol/openid-connect/token" \
  --client-id "lottery-api" \
  --client-secret "your-client-secret" \
  --username "witness1@lottery.org" \
  --password "witness-password"
```

**Prerequisites:**
- User account in Keycloak with witness role
- Server configured with `auth_method: "oidc"`

## Configuration via Environment Variables

Instead of passing credentials as flags, use environment variables:

```bash
export KEYCLOAK_URL="https://keycloak.example.com/realms/lottery/protocol/openid-connect/token"
export CLIENT_ID="lottery-api"
export CLIENT_SECRET="your-secret"
export USERNAME="witness1@lottery.org"
export PASSWORD="witness-password"

./lottery-tlog witness-observe \
  --witness-id "witness1" \
  --server "https://localhost:8443"
```

The tool automatically detects environment variables and uses them.

## Watch Mode

All authentication methods work with watch mode for continuous monitoring:

```bash
./lottery-tlog witness-observe \
  --witness-id "witness1" \
  --server "https://localhost:8443" \
  --watch \
  --interval 10s \
  --keycloak-url "$KEYCLOAK_URL" \
  --client-id "$CLIENT_ID" \
  --client-secret "$CLIENT_SECRET" \
  --username "$USERNAME" \
  --password "$PASSWORD"
```

## Complete Example: Keycloak mTLS Setup

### 1. Generate Witness Certificate

```bash
# Generate witness private key
openssl genrsa -out witness1-key.pem 4096

# Generate CSR
openssl req -new -key witness1-key.pem -out witness1.csr \
  -subj "/C=US/ST=State/L=City/O=LotteryOrg/CN=witness1@lottery.org"

# Sign with CA
openssl x509 -req -in witness1.csr \
  -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out witness1-cert.pem \
  -days 365 -sha256

# Initialize witness in lottery system
./lottery-tlog witness-init \
  --witness-id "witness1" \
  --cert witness1-cert.pem \
  --key witness1-key.pem
```

### 2. Configure Keycloak

1. **Create User**: `witness1@lottery.org`
2. **Assign Role**: `lottery-witness`
3. **Configure X.509**: Map certificate CN to username
4. **Import CA**: Add to Keycloak trusted certificates

### 3. Observe with Keycloak

```bash
./lottery-tlog witness-observe \
  --witness-id "witness1" \
  --server "https://localhost:8443" \
  --keycloak-url "https://keycloak.example.com/realms/lottery/protocol/openid-connect/token" \
  --client-id "lottery-api" \
  --client-secret "YourClientSecretFromKeycloak" \
  --username "witness1@lottery.org" \
  --password "SecurePassword123"
```

### Output:
```
📋 New draws to review (0 → 769):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Seq No: 31 | Code: 302
  Text: Draw configuration.
  Game: 90, Draw: 0, Subdraw: 4
  Timestamp: 2025-10-15 09:21:17
  ...

✓ Tree state observed and signed by witness: witness1
  Tree Size: 769
  Tree Hash: 9250e996e32e7e0b...
  Timestamp: 2026-01-21 14:30:00
```

## Authentication Flow

### mTLS Only
```
Witness → [mTLS + Cert] → Lottery API
```

### Keycloak Hybrid (mTLS → JWT)
```
Witness → [mTLS + Cert] → Keycloak → [JWT Token]
Witness → [JWT Token] → Lottery API
```

### Keycloak Password (JWT Only)
```
Witness → [Username/Password] → Keycloak → [JWT Token]
Witness → [JWT Token] → Lottery API
```

## Benefits of Each Method

### Direct mTLS
- ✅ Simple setup
- ✅ No token management
- ❌ Certificate must be presented on every request
- ❌ No centralized identity management

### Keycloak Hybrid (mTLS → JWT)
- ✅ Strong initial authentication (certificate)
- ✅ Scalable (JWT tokens)
- ✅ Centralized identity and audit
- ✅ Token refresh support
- ❌ More complex setup

### Keycloak Password (JWT Only)
- ✅ No certificate management
- ✅ Easy user onboarding
- ✅ Centralized identity
- ❌ Password-based (weaker than certificates)

## Troubleshooting

### "Failed to create authenticated client"
- Check if witness certificate exists: `.lottery-data/witnesses/witness1/`
- Verify Keycloak URL is accessible
- Test credentials with curl

### "Keycloak authentication failed"
- Verify client secret is correct
- Check username/password in Keycloak
- Ensure user has `lottery-witness` role
- Check certificate is trusted in Keycloak (for mTLS)

### "Token expired"
Currently tokens are used for single observation. For watch mode, tokens are obtained once at start. Future enhancement: automatic token refresh.

## See Also

- [KEYCLOAK_MTLS.md](KEYCLOAK_MTLS.md) - Complete Keycloak setup guide
- [KEYCLOAK_MTLS_QUICKSTART.md](KEYCLOAK_MTLS_QUICKSTART.md) - Quick reference
- [OIDC_AUTH.md](../OIDC_AUTH.md) - OIDC authentication overview
