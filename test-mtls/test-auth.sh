#!/bin/bash
# Test authentication scenarios with Keycloak mTLS

set -e

KEYCLOAK_URL="https://localhost:8443"
TOKEN_URL="$KEYCLOAK_URL/realms/lottery/protocol/openid-connect/token"
CA_CERT="./ca/ca-cert.pem"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🧪 Testing Keycloak mTLS Authentication${NC}"
echo "========================================"
echo ""

# Check if Keycloak is running
echo -e "${YELLOW}Checking if Keycloak is ready...${NC}"
if curl -k -s --max-time 5 "$KEYCLOAK_URL/health/ready" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Keycloak is ready${NC}"
else
    echo -e "${RED}❌ Keycloak is not ready. Start it with: docker-compose up -d${NC}"
    exit 1
fi

echo ""
echo "========================================"
echo ""

# Test 1: Password grant WITHOUT client certificate
echo -e "${BLUE}Test 1: Password grant WITHOUT client certificate${NC}"
echo "Command: curl --cacert (CA only, no client cert)"
echo ""

RESPONSE=$(curl -s --cacert "$CA_CERT" \
  -X POST "$TOKEN_URL" \
  -d "grant_type=password" \
  -d "client_id=lottery-witness" \
  -d "username=witness1@example.com" \
  -d "password=password123")

if echo "$RESPONSE" | jq -e '.access_token' > /dev/null 2>&1; then
    echo -e "${GREEN}✅ SUCCESS: Token received without client certificate${NC}"
    ACCESS_TOKEN=$(echo "$RESPONSE" | jq -r '.access_token')
    REFRESH_TOKEN=$(echo "$RESPONSE" | jq -r '.refresh_token')
    EXPIRES_IN=$(echo "$RESPONSE" | jq -r '.expires_in')
    echo "   Access Token: ${ACCESS_TOKEN:0:50}..."
    echo "   Refresh Token: ${REFRESH_TOKEN:0:50}..."
    echo "   Expires In: ${EXPIRES_IN}s"
else
    echo -e "${RED}❌ FAILED: $(echo $RESPONSE | jq -r '.error_description // .error // "Unknown error"')${NC}"
fi

echo ""
echo "========================================"
echo ""

# Test 2: Password grant WITH client certificate
echo -e "${BLUE}Test 2: Password grant WITH client certificate${NC}"
echo "Command: curl --cacert + --cert (both CA and client cert)"
echo ""

RESPONSE=$(curl -s --cacert "$CA_CERT" \
  --cert ./client/witness1-combined.pem \
  -X POST "$TOKEN_URL" \
  -d "grant_type=password" \
  -d "client_id=lottery-witness" \
  -d "username=witness1@example.com" \
  -d "password=password123")

if echo "$RESPONSE" | jq -e '.access_token' > /dev/null 2>&1; then
    echo -e "${GREEN}✅ SUCCESS: Token received with client certificate${NC}"
    ACCESS_TOKEN_MTLS=$(echo "$RESPONSE" | jq -r '.access_token')
    echo "   Access Token: ${ACCESS_TOKEN_MTLS:0:50}..."
    
    # Decode JWT to see if certificate info is included
    echo ""
    echo "   JWT Claims:"
    echo "$ACCESS_TOKEN_MTLS" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.' | head -n 10 | sed 's/^/     /'
else
    echo -e "${RED}❌ FAILED: $(echo $RESPONSE | jq -r '.error_description // .error // "Unknown error"')${NC}"
fi

echo ""
echo "========================================"
echo ""

# Test 3: Refresh token grant
if [ ! -z "$REFRESH_TOKEN" ]; then
    echo -e "${BLUE}Test 3: Refresh token grant${NC}"
    echo "Command: Using refresh_token from Test 1"
    echo ""
    
    RESPONSE=$(curl -s --cacert "$CA_CERT" \
      -X POST "$TOKEN_URL" \
      -d "grant_type=refresh_token" \
      -d "client_id=lottery-witness" \
      -d "refresh_token=$REFRESH_TOKEN")
    
    if echo "$RESPONSE" | jq -e '.access_token' > /dev/null 2>&1; then
        echo -e "${GREEN}✅ SUCCESS: Token refreshed successfully${NC}"
        NEW_ACCESS_TOKEN=$(echo "$RESPONSE" | jq -r '.access_token')
        NEW_REFRESH_TOKEN=$(echo "$RESPONSE" | jq -r '.refresh_token')
        echo "   New Access Token: ${NEW_ACCESS_TOKEN:0:50}..."
        echo "   New Refresh Token: ${NEW_REFRESH_TOKEN:0:50}..."
        echo "   Token Rotated: $([ "$REFRESH_TOKEN" != "$NEW_REFRESH_TOKEN" ] && echo 'Yes' || echo 'No')"
    else
        echo -e "${RED}❌ FAILED: $(echo $RESPONSE | jq -r '.error_description // .error // "Unknown error"')${NC}"
    fi
else
    echo -e "${YELLOW}⊘ Test 3 SKIPPED: No refresh token from Test 1${NC}"
fi

echo ""
echo "========================================"
echo ""

# Test 4: Different user with their certificate
echo -e "${BLUE}Test 4: Different user (witness2) with matching certificate${NC}"
echo "Command: witness2 credentials + witness2 certificate"
echo ""

RESPONSE=$(curl -s --cacert "$CA_CERT" \
  --cert ./client/witness2-combined.pem \
  -X POST "$TOKEN_URL" \
  -d "grant_type=password" \
  -d "client_id=lottery-witness" \
  -d "username=witness2@example.com" \
  -d "password=password123")

if echo "$RESPONSE" | jq -e '.access_token' > /dev/null 2>&1; then
    echo -e "${GREEN}✅ SUCCESS: witness2 authenticated with certificate${NC}"
    ACCESS_TOKEN_W2=$(echo "$RESPONSE" | jq -r '.access_token')
    echo "   Access Token: ${ACCESS_TOKEN_W2:0:50}..."
else
    echo -e "${RED}❌ FAILED: $(echo $RESPONSE | jq -r '.error_description // .error // "Unknown error"')${NC}"
fi

echo ""
echo "========================================"
echo ""

# Test 5: Admin user
echo -e "${BLUE}Test 5: Admin user with admin certificate${NC}"
echo "Command: admin credentials + admin certificate"
echo ""

RESPONSE=$(curl -s --cacert "$CA_CERT" \
  --cert ./client/admin1-combined.pem \
  -X POST "$TOKEN_URL" \
  -d "grant_type=password" \
  -d "client_id=lottery-witness" \
  -d "username=admin1@example.com" \
  -d "password=admin123")

if echo "$RESPONSE" | jq -e '.access_token' > /dev/null 2>&1; then
    echo -e "${GREEN}✅ SUCCESS: admin authenticated with certificate${NC}"
    ACCESS_TOKEN_ADMIN=$(echo "$RESPONSE" | jq -r '.access_token')
    echo "   Access Token: ${ACCESS_TOKEN_ADMIN:0:50}..."
    
    # Check roles in JWT
    echo ""
    echo "   Roles in JWT:"
    echo "$ACCESS_TOKEN_ADMIN" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.roles[]' | sed 's/^/     - /'
else
    echo -e "${RED}❌ FAILED: $(echo $RESPONSE | jq -r '.error_description // .error // "Unknown error"')${NC}"
fi

echo ""
echo "========================================"
echo ""

# Test 6: Invalid credentials
echo -e "${BLUE}Test 6: Invalid credentials (should fail)${NC}"
echo "Command: Wrong password"
echo ""

RESPONSE=$(curl -s --cacert "$CA_CERT" \
  -X POST "$TOKEN_URL" \
  -d "grant_type=password" \
  -d "client_id=lottery-witness" \
  -d "username=witness1@example.com" \
  -d "password=wrongpassword")

if echo "$RESPONSE" | jq -e '.error' > /dev/null 2>&1; then
    echo -e "${GREEN}✅ EXPECTED FAILURE: Authentication rejected${NC}"
    echo "   Error: $(echo $RESPONSE | jq -r '.error_description // .error')"
else
    echo -e "${RED}❌ UNEXPECTED: Authentication succeeded with wrong password!${NC}"
fi

echo ""
echo "========================================"
echo ""

# Summary
echo -e "${BLUE}📊 Test Summary${NC}"
echo "========================================"
echo ""
echo "Keycloak Configuration:"
echo "  • Realm: lottery"
echo "  • Token Endpoint: $TOKEN_URL"
echo "  • Client Auth: request (optional mTLS)"
echo "  • Access Token Lifetime: 15 minutes"
echo "  • Refresh Token Lifetime: 60 minutes"
echo ""
echo "Test Users:"
echo "  • witness1@example.com / password123 (role: witness)"
echo "  • witness2@example.com / password123 (role: witness)"
echo "  • admin1@example.com / admin123 (role: admin)"
echo ""
echo "Client Certificates:"
echo "  • witness1: client/witness1-combined.pem"
echo "  • witness2: client/witness2-combined.pem"
echo "  • admin1: client/admin1-combined.pem"
echo ""
echo -e "${GREEN}✅ Testing complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Test with witness observer:"
echo "     ../lottery-tlog witness-observe --witness-id witness1 \\"
echo "       --server https://localhost:8080 \\"
echo "       --keycloak-url $TOKEN_URL \\"
echo "       --client-id lottery-witness \\"
echo "       --username witness1@example.com \\"
echo "       --password password123"
echo ""
echo "  2. View Keycloak admin console:"
echo "     https://localhost:8443/admin"
echo "     Username: admin"
echo "     Password: admin"
echo ""
