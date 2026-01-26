#!/bin/bash
# Generate test certificates for Keycloak mTLS testing

set -e

echo "🔐 Generating test certificates for Keycloak mTLS..."

# Create directories
mkdir -p certs ca client server

# 1. Create Certificate Authority (CA)
echo "📋 Step 1: Creating Certificate Authority..."
openssl genrsa -out ca/ca-key.pem 4096

openssl req -new -x509 -days 3650 -key ca/ca-key.pem -out ca/ca-cert.pem \
  -subj "/C=US/ST=Test/L=Test/O=LotteryLog Test/OU=CA/CN=Test CA"

echo "✅ CA certificate created: ca/ca-cert.pem"

# 2. Create Keycloak Server Certificate
echo ""
echo "📋 Step 2: Creating Keycloak server certificate..."
openssl genrsa -out server/keycloak-key.pem 2048

openssl req -new -key server/keycloak-key.pem -out server/keycloak.csr \
  -subj "/C=US/ST=Test/L=Test/O=LotteryLog Test/OU=Keycloak/CN=localhost"

# Create server cert config for SAN
cat > server/keycloak.cnf <<EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = US
ST = Test
L = Test
O = LotteryLog Test
OU = Keycloak
CN = localhost

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = keycloak
DNS.3 = lottery-tlog
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in server/keycloak.csr -CA ca/ca-cert.pem -CAkey ca/ca-key.pem \
  -CAcreateserial -out server/keycloak-cert.pem -days 365 \
  -extensions req_ext -extfile server/keycloak.cnf

# Create keystore for Keycloak (PKCS12 format)
openssl pkcs12 -export -in server/keycloak-cert.pem -inkey server/keycloak-key.pem \
  -out server/keycloak-keystore.p12 -name keycloak -password pass:changeit

# Create truststore with CA cert
keytool -import -trustcacerts -noprompt -alias ca -file ca/ca-cert.pem \
  -keystore server/keycloak-truststore.jks -storepass changeit

echo "✅ Keycloak server certificate created"
echo "   - Certificate: server/keycloak-cert.pem"
echo "   - Keystore: server/keycloak-keystore.p12"
echo "   - Truststore: server/keycloak-truststore.jks"

# 3. Create Client Certificates (for witnesses)
echo ""
echo "📋 Step 3: Creating client certificates..."

for client_id in witness1 witness2 admin1; do
  echo "  Creating certificate for: $client_id"
  
  # Generate client key
  openssl genrsa -out client/${client_id}-key.pem 2048
  
  # Generate CSR
  openssl req -new -key client/${client_id}-key.pem -out client/${client_id}.csr \
    -subj "/C=US/ST=Test/L=Test/O=LotteryLog Test/OU=Clients/CN=${client_id}@example.com"
  
  # Sign with CA
  openssl x509 -req -in client/${client_id}.csr -CA ca/ca-cert.pem -CAkey ca/ca-key.pem \
    -CAcreateserial -out client/${client_id}-cert.pem -days 365
  
  # Create PKCS12 bundle (for browsers)
  openssl pkcs12 -export -in client/${client_id}-cert.pem -inkey client/${client_id}-key.pem \
    -out client/${client_id}.p12 -name "$client_id" -password pass:changeit
  
  echo "  ✅ $client_id: client/${client_id}-cert.pem"
done

# 4. Create combined certificate files for easy use
echo ""
echo "📋 Step 4: Creating combined certificate files..."

for client_id in witness1 witness2 admin1; do
  cat client/${client_id}-cert.pem client/${client_id}-key.pem > client/${client_id}-combined.pem
  echo "  ✅ client/${client_id}-combined.pem"
done

# 5. Display certificate information
echo ""
echo "📋 Step 5: Certificate Summary"
echo "============================================"
echo ""
echo "Certificate Authority:"
openssl x509 -in ca/ca-cert.pem -noout -subject -issuer -dates

echo ""
echo "Keycloak Server Certificate:"
openssl x509 -in server/keycloak-cert.pem -noout -subject -issuer -dates

echo ""
echo "Client Certificates:"
for client_id in witness1 witness2 admin1; do
  echo "  $client_id:"
  openssl x509 -in client/${client_id}-cert.pem -noout -subject -dates | sed 's/^/    /'
done

# 6. Create certificate installation instructions
cat > certs/INSTALL.md <<EOF
# Certificate Installation Guide

## For Keycloak (Docker)

The certificates are automatically mounted via docker-compose.yml:
- Keystore: \`/opt/keycloak/conf/keycloak-keystore.p12\`
- Truststore: \`/opt/keycloak/conf/keycloak-truststore.jks\`

## For Witness Observer (Go Client)

\`\`\`bash
# Use client certificate with witness observer
../lottery-tlog witness-observe \\
  --witness-id witness1 \\
  --server https://localhost:8443 \\
  --keycloak-url https://localhost:8443/realms/lottery/protocol/openid-connect/token \\
  --client-id lottery-witness \\
  --username witness1@example.com \\
  --password password123
\`\`\`

The client certificate will be loaded from:
- Certificate: \`client/witness1-cert.pem\`
- Key: \`client/witness1-key.pem\`

Or use the combined file:
\`\`\`bash
export WITNESS_CERT=\$(pwd)/client/witness1-combined.pem
\`\`\`

## For Browser Testing

1. Import the PKCS12 file:
   - Chrome/Edge: Settings → Privacy → Manage certificates → Import
   - Firefox: Preferences → Privacy → View Certificates → Your Certificates → Import

2. Import files:
   - \`client/witness1.p12\` (password: changeit)
   - \`client/witness2.p12\` (password: changeit)
   - \`client/admin1.p12\` (password: changeit)

3. Also import CA certificate (to trust Keycloak's server cert):
   - Chrome/Edge: Settings → Privacy → Manage certificates → Authorities → Import
   - Firefox: Preferences → Privacy → View Certificates → Authorities → Import
   - File: \`ca/ca-cert.pem\`

## For curl Testing

\`\`\`bash
# Get token using client certificate
curl -v --cacert ca/ca-cert.pem \\
  --cert client/witness1-combined.pem \\
  -X POST https://localhost:8443/realms/lottery/protocol/openid-connect/token \\
  -d "grant_type=password" \\
  -d "client_id=lottery-witness" \\
  -d "username=witness1@example.com" \\
  -d "password=password123"
\`\`\`

## Certificate Details

- **CA Certificate:** \`ca/ca-cert.pem\`
  - Valid for: 10 years
  - Used to sign all other certificates

- **Server Certificate:** \`server/keycloak-cert.pem\`
  - Valid for: 1 year
  - CN: localhost
  - SAN: localhost, keycloak, 127.0.0.1

- **Client Certificates:**
  - witness1: \`client/witness1-cert.pem\` (CN: witness1@example.com)
  - witness2: \`client/witness2-cert.pem\` (CN: witness2@example.com)
  - admin1: \`client/admin1-cert.pem\` (CN: admin1@example.com)
  - Valid for: 1 year

## Security Notes

⚠️ **These are TEST certificates only!**

- All private keys are unencrypted
- Default passwords used (changeit)
- Self-signed CA
- Short validity periods

**DO NOT use these certificates in production!**
EOF

echo ""
echo "============================================"
echo "✅ Certificate generation complete!"
echo ""
echo "Generated files:"
echo "  📁 ca/             - Certificate Authority"
echo "  📁 server/         - Keycloak server certificates"
echo "  📁 client/         - Client certificates (witness1, witness2, admin1)"
echo ""
echo "Next steps:"
echo "  1. Review: cat certs/INSTALL.md"
echo "  2. Start Keycloak: docker-compose up -d"
echo "  3. Test authentication: ./test-auth.sh"
echo ""
