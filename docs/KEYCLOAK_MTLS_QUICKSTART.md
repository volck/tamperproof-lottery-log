# Keycloak mTLS Quick Start

## Summary

This approach combines X.509 certificate authentication with JWT tokens:
- **Clients authenticate to Keycloak using mTLS** (strong cryptographic identity)
- **Keycloak issues JWT tokens** (stateless, scalable API access)
- **API validates JWT tokens** (no session storage needed)

## Configuration

### config.yaml
```yaml
server:
  host: "0.0.0.0"
  port: 8443
  auth_method: "oidc"
  
  tls:
    cert_file: "certs/server-cert.pem"
    key_file: "certs/server-key.pem"
    ca_file: "certs/ca-cert.pem"
  
  oidc:
    enabled: true
    issuer_url: "https://keycloak.example.com/realms/lottery"
    client_id: "lottery-api"
    client_secret: "your-keycloak-client-secret"
    redirect_url: "https://localhost:8443/auth/callback"
    
    # Require client certificate for Keycloak token acquisition
    require_client_cert_for_token: true
    
    # Map emails to roles
    admin_emails:
      - "admin@lottery.org"
    witness_emails:
      - "witness1@lottery.org"
```

### Environment Variables
```bash
export OIDC_ISSUER_URL="https://keycloak.example.com/realms/lottery"
export OIDC_CLIENT_ID="lottery-api"
export OIDC_CLIENT_SECRET="your-secret-from-keycloak"
export OIDC_REDIRECT_URL="https://localhost:8443/auth/callback"
export ADMIN_EMAIL="admin@lottery.org"
```

## Keycloak Setup Steps

1. **Create Realm**: `lottery`

2. **Enable X.509 Authentication**:
   - Authentication → Flows → Browser Flow
   - Add: X509/Validate Username Form
   - Requirement: ALTERNATIVE

3. **Create Client**:
   ```
   Client ID: lottery-api
   Access Type: confidential
   Valid Redirect URIs: https://localhost:8443/*
   ```

4. **Configure Client Certificate Auth**:
   - Client → Credentials → Client Authenticator: X509 Certificate
   - Subject DN Pattern: `CN=(.*)`

5. **Create Roles**: `lottery-admin`, `lottery-witness`

6. **Create User**:
   - Username: matches certificate CN (e.g., `admin@lottery.org`)
   - Assign roles

7. **Import CA Certificate**:
   - Realm Settings → Keys → Add provider → Import certificate

## Client Example

### Get Token from Keycloak
```bash
# Present certificate to Keycloak and get JWT
curl --cert admin-cert.pem --key admin-key.pem --cacert ca-cert.pem \
  https://keycloak.example.com/realms/lottery/protocol/openid-connect/token \
  -d "grant_type=password" \
  -d "client_id=lottery-api" \
  -d "client_secret=your-secret" \
  -d "username=admin@lottery.org" \
  -d "password=admin-pass" \
  | jq -r .access_token > token.txt
```

### Use Token with Lottery API
```bash
# Call API with JWT (no certificate needed)
curl -H "Authorization: Bearer $(cat token.txt)" \
  https://localhost:8443/api/admin/draw \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-01-21T14:00:00Z",
    "seqno": 1001,
    "ip": "192.168.1.100",
    "severity": "harmless",
    "message": {
      "code": 300,
      "text": "Numbers drawn",
      "game": 7,
      "draw": 1234,
      "subdraw": 1,
      "values": [5, 12, 23, 34, 45]
    },
    "mac": "generated-mac-here"
  }'
```

## Benefits

✅ **Strong Authentication**: Cryptographic certificates for initial auth  
✅ **Scalable**: Stateless JWT tokens, no session storage  
✅ **Standards-Based**: OAuth2/OIDC compliance  
✅ **Centralized**: Single source of truth for identity  
✅ **Flexible**: Can mix web browsers and API clients  
✅ **Auditable**: All auth events logged in Keycloak  

## Authentication Flow

```
1. Client → Keycloak (with mTLS)
   Certificate: CN=admin@lottery.org
   
2. Keycloak validates certificate
   - Checks CA signature
   - Maps CN to user
   - Checks user roles
   
3. Keycloak → Client (JWT Token)
   {
     "access_token": "eyJ...",
     "email": "admin@lottery.org",
     "roles": ["lottery-admin"]
   }
   
4. Client → Lottery API (with JWT)
   Authorization: Bearer eyJ...
   
5. Lottery API validates JWT
   - Verifies signature (Keycloak public key)
   - Checks expiration
   - Extracts roles
   
6. Lottery API → Client (Response)
   Draw added successfully
```

## See Full Documentation

For complete setup instructions, see:
- [docs/KEYCLOAK_MTLS.md](KEYCLOAK_MTLS.md) - Complete guide
- [OIDC_AUTH.md](../OIDC_AUTH.md) - OIDC authentication details
