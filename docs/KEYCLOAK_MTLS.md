# Keycloak with mTLS Authentication

This guide shows how to configure Keycloak to require X.509 client certificates for token acquisition, providing a secure hybrid authentication approach.

## Architecture

```
┌──────────┐              ┌──────────┐              ┌─────────────┐
│  Client  │─────mTLS────▶│ Keycloak │              │   Lottery   │
│   +Cert  │              │  Server  │              │  API Server │
└──────────┘              └──────────┘              └─────────────┘
     │                          │                          │
     │  1. Present Certificate  │                          │
     ├─────────────────────────▶│                          │
     │                          │                          │
     │  2. Receive JWT Token    │                          │
     │◀─────────────────────────┤                          │
     │                          │                          │
     │  3. API Call + JWT       │                          │
     ├────────────────────────────────────────────────────▶│
     │                          │                          │
     │  4. Validate JWT         │                          │
     │                          │◀─────────────────────────│
     │                          │                          │
     │  5. API Response         │                          │
     │◀────────────────────────────────────────────────────┤
```

## Benefits

1. **Strong Initial Authentication**: X.509 certificates provide cryptographic proof of identity
2. **Scalability**: JWT tokens don't require session storage or lookups
3. **Standard Protocol**: Uses standard OAuth2/OIDC flows
4. **Centralized Identity**: Keycloak manages all authentication and authorization
5. **Token Revocation**: Keycloak can revoke tokens if needed
6. **Audit Trail**: All authentication events logged in Keycloak

## Keycloak Configuration

### 1. Create Realm

```bash
# Create a realm for lottery system
Realm Name: lottery
Enabled: ON
```

### 2. Enable X.509 Client Certificate Authentication

In Keycloak Admin Console:

1. Navigate to **Realm Settings** → **Client Registration**
2. Go to **Authentication** → **Flows**
3. Create a new flow or modify "Direct Grant" flow:
   - Add **X509/Validate Username Form**
   - Set **Requirement**: ALTERNATIVE or REQUIRED

### 3. Configure X.509 Authentication

1. Go to **Authentication** → **Bindings**
2. Set **Browser Flow**: browser (with X509)
3. Set **Direct Grant Flow**: direct grant (with X509)

4. Configure X.509 settings:
   - **User Identity Source**: Match SubjectDN using regular expression
   - **Regular Expression**: `CN=(.*?)(?:,|$)`
   - **User Mapping Method**: Username or email
   - **A name of user attribute**: email or username

### 4. Create Client for Lottery API

```yaml
Client ID: lottery-api
Client Protocol: openid-connect
Access Type: confidential
Standard Flow Enabled: ON
Direct Access Grants Enabled: ON
Service Accounts Enabled: ON

# Authentication
Client Authenticator: X509 Certificate
Subject DN: CN=lottery-admin,O=LotteryOrg,C=US  # Or use regex

# Valid Redirect URIs
https://localhost:8443/auth/callback
https://lottery-api.example.com/auth/callback
```

### 5. Configure Client Certificate Authentication

In **Client Details** → **Credentials** → **Client Authenticator**:
```
Type: X509 Certificate
Subject DN: CN=(.*)  # Regex to match certificate CN
```

### 6. Create Roles

```yaml
Roles:
  - lottery-admin    # Can add draws
  - lottery-witness  # Can observe and cosign
  - lottery-viewer   # Read-only access (implicit for all authenticated users)
```

### 7. Create Users and Assign Certificates

For each user:
1. **Users** → **Add User**
2. Set email and username matching certificate CN or Subject
3. **Role Mappings** → Assign appropriate roles
4. Link certificate to user via **X509** tab or by username/email matching

### 8. Configure Token Settings

**Realm Settings** → **Tokens**:
```yaml
Access Token Lifespan: 15 minutes
Refresh Token Max: 1 hour
SSO Session Idle: 30 minutes
SSO Session Max: 10 hours
Client Session Idle: 15 minutes
Client Session Max: 1 day
```

## Lottery API Configuration

Update `config.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 8443
  
  # Use OIDC authentication
  auth_method: "oidc"
  
  tls:
    cert_file: "certs/server-cert.pem"
    key_file: "certs/server-key.pem"
    ca_file: "certs/ca-cert.pem"
  
  oidc:
    enabled: true
    # Keycloak realm endpoint
    issuer_url: "https://keycloak.example.com/realms/lottery"
    client_id: "lottery-api"
    client_secret: "your-client-secret"
    redirect_url: "https://localhost:8443/auth/callback"
    
    # Enable mTLS requirement for Keycloak token acquisition
    # When true, clients must present certificate to get token from Keycloak
    require_client_cert_for_token: true
    
    # Role-based access (maps to Keycloak roles)
    admin_emails:
      - "admin@lottery.org"
    witness_emails:
      - "witness1@lottery.org"
      - "witness2@lottery.org"
```

## Certificate Generation

### 1. Create CA Certificate

```bash
# Generate CA private key
openssl genrsa -out ca-key.pem 4096

# Generate CA certificate
openssl req -new -x509 -days 3650 -key ca-key.pem -out ca-cert.pem \
  -subj "/C=US/ST=State/L=City/O=LotteryOrg/CN=Lottery CA"
```

### 2. Create Server Certificate

```bash
# Generate server private key
openssl genrsa -out server-key.pem 4096

# Generate CSR
openssl req -new -key server-key.pem -out server.csr \
  -subj "/C=US/ST=State/L=City/O=LotteryOrg/CN=lottery-api.example.com"

# Sign with CA
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -days 365 \
  -sha256 -extfile <(echo "subjectAltName=DNS:localhost,DNS:lottery-api.example.com")
```

### 3. Create Client Certificates

For admin:
```bash
# Generate admin private key
openssl genrsa -out admin-key.pem 4096

# Generate admin CSR
openssl req -new -key admin-key.pem -out admin.csr \
  -subj "/C=US/ST=State/L=City/O=LotteryOrg/CN=admin@lottery.org"

# Sign with CA
openssl x509 -req -in admin.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out admin-cert.pem -days 365 -sha256
```

For witnesses:
```bash
# Generate witness private key
openssl genrsa -out witness1-key.pem 4096

# Generate witness CSR
openssl req -new -key witness1-key.pem -out witness1.csr \
  -subj "/C=US/ST=State/L=City/O=LotteryOrg/CN=witness1@lottery.org"

# Sign with CA
openssl x509 -req -in witness1.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out witness1-cert.pem -days 365 -sha256
```

### 4. Import CA to Keycloak

In Keycloak:
1. **Realm Settings** → **Keys** → **Providers**
2. Add **rsa** provider
3. Import `ca-cert.pem` as trusted certificate

## Client Usage

### Direct Grant with Certificate

```bash
# Get token using client certificate
curl --cert admin-cert.pem --key admin-key.pem \
  --cacert ca-cert.pem \
  -X POST "https://keycloak.example.com/realms/lottery/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=lottery-api" \
  -d "client_secret=your-client-secret" \
  -d "username=admin@lottery.org" \
  -d "password=admin-password"
```

Response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 900,
  "refresh_expires_in": 3600,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer"
}
```

### Use Token for API Calls

```bash
# Store token
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Call lottery API
curl -H "Authorization: Bearer $TOKEN" \
  https://localhost:8443/api/admin/draw \
  -X POST -d @draw.json
```

## Browser Flow with Certificate

For web-based authentication:

1. User navigates to: `https://localhost:8443/auth/login`
2. Browser presents client certificate to Keycloak
3. Keycloak validates certificate and creates session
4. User is redirected back to application with authorization code
5. Application exchanges code for JWT token
6. Application stores JWT in secure cookie

## JWT Token Validation

The lottery API validates JWT tokens by:

1. Verifying signature using Keycloak's public key (fetched from `.well-known/openid-configuration`)
2. Checking token expiration
3. Validating issuer matches Keycloak realm
4. Extracting user email and roles from token claims
5. Enforcing role-based access control

## Security Best Practices

1. **Certificate Revocation**: Implement CRL or OCSP checking
2. **Short Token Lifetime**: Keep access tokens short-lived (15 min)
3. **Refresh Tokens**: Use refresh tokens for long-running sessions
4. **Token Binding**: Bind tokens to client certificates using thumbprint
5. **Audit Logging**: Log all authentication and token events
6. **Certificate Storage**: Store private keys in HSM or secure key storage
7. **Regular Rotation**: Rotate certificates before expiration

## Troubleshooting

### Certificate Not Accepted

```bash
# Verify certificate chain
openssl verify -CAfile ca-cert.pem admin-cert.pem

# Check certificate details
openssl x509 -in admin-cert.pem -text -noout
```

### Token Validation Fails

```bash
# Decode JWT to check claims
echo $TOKEN | cut -d. -f2 | base64 -d | jq .

# Check Keycloak keys
curl https://keycloak.example.com/realms/lottery/protocol/openid-connect/certs
```

### Debug Keycloak Logs

```bash
# Enable debug logging in Keycloak
# standalone.xml or standalone-ha.xml
<logger category="org.keycloak">
    <level name="DEBUG"/>
</logger>
```

## Complete Example

See `examples/keycloak-mtls/` for:
- Full Keycloak realm export
- Certificate generation scripts
- Client examples in various languages
- Docker Compose setup
