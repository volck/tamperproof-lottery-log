# OIDC Authentication Guide

The lottery transparency log server now supports **OpenID Connect (OIDC)** as the default authentication method for secure, modern authentication.

## Configuration

Edit `config.yaml` to configure OIDC:

```yaml
server:
  auth_method: "oidc"  # Use "oidc" (default) or "mtls"
  
  oidc:
    enabled: true
    issuer_url: "https://accounts.google.com"  # Or your OIDC provider
    client_id: "your-client-id"
    client_secret: "your-client-secret"
    redirect_url: "https://localhost:8443/auth/callback"
    
    # Optional: Restrict to specific email domains
    allowed_domains:
      - "example.com"
      - "lottery.org"
    
    # Admin users (can add draws)
    admin_emails:
      - "admin@example.com"
    
    # Witness users (can observe and sign)
    witness_emails:
      - "witness1@example.com"
      - "witness2@example.com"
```

### Environment Variables

You can use environment variables for sensitive values:

```bash
export OIDC_ISSUER_URL="https://accounts.google.com"
export OIDC_CLIENT_ID="your-client-id.apps.googleusercontent.com"
export OIDC_CLIENT_SECRET="your-secret"
export OIDC_REDIRECT_URL="https://localhost:8443/auth/callback"
export ADMIN_EMAIL="admin@example.com"
```

## Supported OIDC Providers

- **Google**: `https://accounts.google.com`
- **Microsoft Azure AD**: `https://login.microsoftonline.com/{tenant-id}/v2.0`
- **Okta**: `https://{your-domain}.okta.com`
- **Auth0**: `https://{your-domain}.auth0.com`
- **Keycloak**: `https://{your-domain}/realms/{realm-name}`
- Any standard OIDC-compliant provider

## API Endpoints

### Public Endpoints (No Authentication)
- `GET /health` - Health check
- `GET /api/tree/info` - Get tree size and hash
- `GET /api/draws` - List all draws
- `GET /api/draws/{index}` - Get specific draw
- `GET /api/draws/since/{size}` - Get draws since tree size
- `GET /api/status` - Get comprehensive status

### Authentication Endpoints
- `GET /auth/login` - Initiate OIDC login
- `GET /auth/callback` - OIDC callback handler
- `POST /auth/logout` - Logout and clear session
- `GET /auth/user` - Get current user info

### Witness Endpoints (Requires Authentication)
- `POST /api/witness/observe` - Submit witness observation
- `GET /api/witness/observations` - Get witness observations
- `GET /api/witness/cosignatures` - Get cosignatures
- `POST /api/witness/heartbeat` - Submit heartbeat

### Admin Endpoints (Requires Admin Role)
- `POST /api/admin/draw` - Add new draw event

## Authentication Flow

1. **Login**: Navigate to `https://localhost:8443/auth/login`
2. **Redirect**: User is redirected to OIDC provider (e.g., Google)
3. **Authenticate**: User logs in with their OIDC provider
4. **Callback**: Provider redirects back to `/auth/callback`
5. **Session**: Server creates a session cookie (valid 24 hours)
6. **Access**: User can now access protected endpoints

## Role-Based Access Control

- **Public**: Anyone can read lottery draws and verify the log
- **Witness**: Can observe draws and submit cosignatures
- **Admin**: Can add new draws and perform all witness operations

Roles are assigned based on email address matching in the configuration.

## Example: Google OIDC Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable "Google+ API"
4. Create OAuth 2.0 credentials:
   - Application type: Web application
   - Authorized redirect URIs: `https://localhost:8443/auth/callback`
5. Copy Client ID and Client Secret to your config

## Example: Azure AD Setup

1. Go to [Azure Portal](https://portal.azure.com/)
2. Navigate to Azure Active Directory > App registrations
3. Create a new registration:
   - Name: "Lottery Transparency Log"
   - Redirect URI: `https://localhost:8443/auth/callback`
4. Copy Application (client) ID and Directory (tenant) ID
5. Create a client secret under "Certificates & secrets"
6. Set issuer URL to: `https://login.microsoftonline.com/{tenant-id}/v2.0`

## Switching Between OIDC and mTLS

To use mTLS (certificate-based authentication) instead:

```yaml
server:
  auth_method: "mtls"
  tls:
    require_client_cert: true
```

## Security Considerations

- **HTTPS Required**: Always use HTTPS in production
- **Email Verification**: Only verified emails are allowed
- **Session Expiry**: Sessions expire after 24 hours
- **Domain Restrictions**: Use `allowed_domains` to restrict access
- **Secure Cookies**: Sessions use HttpOnly, Secure, SameSite cookies

## Testing

Start the server:
```bash
./lottery-tlog server
```

Test authentication:
```bash
# Check if authenticated
curl -b cookies.txt https://localhost:8443/auth/user

# Login (will redirect to OIDC provider)
curl -L https://localhost:8443/auth/login

# Access protected endpoint
curl -b cookies.txt https://localhost:8443/api/admin/draw -X POST -d @draw.json
```
