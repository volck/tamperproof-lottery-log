# Certificate Installation Guide

## For Keycloak (Docker)

The certificates are automatically mounted via docker-compose.yml:
- Keystore: `/opt/keycloak/conf/keycloak-keystore.p12`
- Truststore: `/opt/keycloak/conf/keycloak-truststore.jks`

## For Witness Observer (Go Client)

```bash
# Use client certificate with witness observer
../lottery-tlog witness-observe \
  --witness-id witness1 \
  --server https://localhost:8443 \
  --keycloak-url https://localhost:8443/realms/lottery/protocol/openid-connect/token \
  --client-id lottery-witness \
  --username witness1@example.com \
  --password password123
```

The client certificate will be loaded from:
- Certificate: `client/witness1-cert.pem`
- Key: `client/witness1-key.pem`

Or use the combined file:
```bash
export WITNESS_CERT=$(pwd)/client/witness1-combined.pem
```

## For Browser Testing

1. Import the PKCS12 file:
   - Chrome/Edge: Settings → Privacy → Manage certificates → Import
   - Firefox: Preferences → Privacy → View Certificates → Your Certificates → Import

2. Import files:
   - `client/witness1.p12` (password: changeit)
   - `client/witness2.p12` (password: changeit)
   - `client/admin1.p12` (password: changeit)

3. Also import CA certificate (to trust Keycloak's server cert):
   - Chrome/Edge: Settings → Privacy → Manage certificates → Authorities → Import
   - Firefox: Preferences → Privacy → View Certificates → Authorities → Import
   - File: `ca/ca-cert.pem`

## For curl Testing

```bash
# Get token using client certificate
curl -v --cacert ca/ca-cert.pem \
  --cert client/witness1-combined.pem \
  -X POST https://localhost:8443/realms/lottery/protocol/openid-connect/token \
  -d "grant_type=password" \
  -d "client_id=lottery-witness" \
  -d "username=witness1@example.com" \
  -d "password=password123"
```

## Certificate Details

- **CA Certificate:** `ca/ca-cert.pem`
  - Valid for: 10 years
  - Used to sign all other certificates

- **Server Certificate:** `server/keycloak-cert.pem`
  - Valid for: 1 year
  - CN: localhost
  - SAN: localhost, keycloak, 127.0.0.1

- **Client Certificates:**
  - witness1: `client/witness1-cert.pem` (CN: witness1@example.com)
  - witness2: `client/witness2-cert.pem` (CN: witness2@example.com)
  - admin1: `client/admin1-cert.pem` (CN: admin1@example.com)
  - Valid for: 1 year

## Security Notes

⚠️ **These are TEST certificates only!**

- All private keys are unencrypted
- Default passwords used (changeit)
- Self-signed CA
- Short validity periods

**DO NOT use these certificates in production!**
