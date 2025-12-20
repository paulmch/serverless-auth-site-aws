# serverless-auth-site-aws

Host a secure static website on AWS for **almost free** - no custom domain required. Serverless authentication with Cognito, server-side session storage, and zero infrastructure to manage.

## Why This Exists

Need a password-protected dashboard or internal tool? Don't want to pay for:
- Custom domain (~$12/year)
- Route53 hosted zone ($0.50/month)
- ACM certificates (free, but requires domain)

This project uses API Gateway's free HTTPS URL + Cognito's hosted login UI.

## Cost Breakdown

| Service | Free Tier | After Free Tier |
|---------|-----------|-----------------|
| API Gateway | 1M requests/month (12 months) | $3.50/million |
| Lambda | 1M requests/month (always free) | $0.20/million |
| Cognito | 50,000 MAU (always free) | $0.0055/MAU |
| S3 | 5GB storage (12 months) | $0.023/GB |
| DynamoDB | 25GB + 25 RCU/WCU (always free) | Pay per request |

**Typical personal project: $0/month**

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Browser   │────▶│ API Gateway │────▶│   Lambda    │
└─────────────┘     └──────┬──────┘     │ Authorizer  │
                          │             └──────┬──────┘
                          ▼                    │
                   ┌─────────────┐            │ JWT
                   │  Cognito    │◀───────────┘ Verify
                   │ Hosted UI   │
                   └─────────────┘
                          │
              ┌───────────┼───────────┐
              ▼           ▼           ▼
        ┌─────────┐ ┌─────────┐ ┌─────────┐
        │   S3    │ │ Lambda  │ │DynamoDB │
        │ Static  │ │   API   │ │Sessions │
        └─────────┘ └─────────┘ └─────────┘
```

## Security Considerations

**This setup is perfect for:**
- Personal projects and dashboards
- Internal tools with few users
- Learning and experimentation
- MVPs and prototypes

**For production with public traffic, add:**
- CloudFront (CDN + DDoS protection)
- AWS WAF (Web Application Firewall)
- Custom domain + ACM certificate

## Server-Side Session Storage

Tokens are stored securely in DynamoDB, **not in browser cookies**:

```
┌─────────────┐                    ┌─────────────┐
│   Browser   │  session_id only   │  DynamoDB   │
│   Cookie    │ ◀────────────────▶ │   Tokens    │
│  (HttpOnly) │                    │ (encrypted) │
└─────────────┘                    └─────────────┘
```

**Security benefits:**
| Aspect | This Implementation |
|--------|-------------------|
| Token visibility | Hidden server-side (not in DevTools) |
| XSS protection | Tokens can't be stolen via JavaScript |
| Session revocation | Delete DynamoDB item = instant logout |
| Audit trail | Track session activity via lastAccessedAt |

The browser only receives an opaque `session_id` UUID in an HttpOnly cookie.

### Additional Session Hardening Options

The current implementation protects against XSS token theft. For higher-security environments, consider these additional measures:

#### 1. IP Address Binding
Bind sessions to the client's IP address. Reject requests from different IPs.

```python
# In auth_callback.py - store IP when creating session
item['clientIp'] = event['requestContext']['identity']['sourceIp']

# In authorizer.py - validate IP matches
if session.get('clientIp') != event['requestContext']['identity']['sourceIp']:
    raise Exception("Unauthorized - IP mismatch")
```

**Trade-off:** Breaks for users on mobile networks or VPNs where IP changes frequently.

#### 2. User-Agent Binding
Bind sessions to the browser's User-Agent string.

```python
# Store User-Agent hash when creating session
import hashlib
ua_hash = hashlib.sha256(headers.get('User-Agent', '').encode()).hexdigest()[:16]
item['uaHash'] = ua_hash

# Validate on each request
if session.get('uaHash') != current_ua_hash:
    raise Exception("Unauthorized - User-Agent mismatch")
```

**Trade-off:** Easy to spoof, but adds friction for casual attackers.

#### 3. Shorter Session TTL with Sliding Expiration
Reduce session lifetime and extend on activity.

```python
# In authorizer.py - extend session on each request
SHORT_TTL = 15 * 60  # 15 minutes
table.update_item(
    Key={'sessionId': session_id},
    UpdateExpression='SET expiresAt = :exp, lastAccessedAt = :now',
    ExpressionAttributeValues={
        ':exp': int(time.time()) + SHORT_TTL,
        ':now': int(time.time())
    }
)
```

**Trade-off:** Users must re-authenticate after 15 minutes of inactivity.

#### 4. Session Revocation API
Add an endpoint to list and revoke active sessions.

```python
# GET /api/auth/sessions - list user's active sessions
# DELETE /api/auth/sessions/{sessionId} - revoke specific session
# DELETE /api/auth/sessions - revoke all sessions (logout everywhere)
```

**Implementation:** Query DynamoDB by userId (requires GSI), delete matching items.

#### 5. Concurrent Session Limits
Limit users to N active sessions, invalidating oldest when exceeded.

```python
# After creating new session, query user's sessions
# If count > MAX_SESSIONS, delete oldest by createdAt
```

#### 6. Device Fingerprinting
Generate a fingerprint from multiple browser attributes (screen size, timezone, plugins, etc.) and validate on each request.

**Trade-off:** Privacy concerns, fingerprints can change, complex to implement reliably.

#### Security Comparison

| Hardening | Prevents | Breaks When |
|-----------|----------|-------------|
| IP binding | Stolen session from different network | VPN, mobile networks, ISP IP rotation |
| UA binding | Casual session theft | Attacker copies User-Agent |
| Short TTL | Long-lived stolen sessions | Legitimate idle users |
| Revocation API | Compromised sessions | Requires user action |
| Session limits | Session accumulation | Multiple legitimate devices |

**Recommendation:** For most internal tools, the current HttpOnly + Secure + SameSite cookie implementation is sufficient. Add IP binding only if users have static IPs (corporate networks).

## Easy SSO Integration

Cognito makes adding SSO trivial. To add Google, Azure AD, or SAML:

1. Create OAuth app in your identity provider
2. Add identity provider in Cognito console
3. Update callback URLs

**No code changes required** - just configuration.

```
Cognito Console → User Pools → [Your Pool] →
Sign-in experience → Federated identity provider sign-in → Add identity provider
```

### Supported Identity Providers
- Google
- Facebook
- Amazon
- Apple
- SAML (Azure AD, Okta, OneLogin, etc.)
- OpenID Connect (any OIDC-compliant provider)

## Quick Start

```bash
# Install dependencies
npm install

# Configure AWS credentials
aws configure

# Bootstrap CDK (first time only)
npx cdk bootstrap

# Deploy (takes ~5 minutes)
npm run deploy

# The output will show your site URL
```

## The Tricky Parts

The Lambda authorizer handles edge cases that trip up most implementations:

1. **Expired access token + valid refresh token** → Allow refresh endpoint
2. **Browser deletes expired cookies** → Detect missing token vs invalid token
3. **Decider endpoint** → Always allowed for refresh flow
4. **JWKS caching** → Avoid Cognito rate limits (1-hour cache)

See `lambda/authorizer.py` for the implementation.

## Project Structure

```
├── lib/
│   └── secure-static-site-stack.ts   # CDK infrastructure
├── lambda/
│   ├── authorizer.py                 # JWT verification
│   ├── auth_callback.py              # OAuth2 callback
│   ├── auth_decider.py               # Token refresh logic
│   ├── api_handler.py                # Example API
│   └── update_cognito_urls.py        # URL configuration
├── frontend/
│   └── src/                          # Static files
└── bin/
    └── app.ts                        # CDK entry point
```

## Adding Users

Since self-signup is disabled (for security), add users via AWS CLI:

```bash
aws cognito-idp admin-create-user \
  --user-pool-id YOUR_USER_POOL_ID \
  --username user@example.com \
  --user-attributes Name=email,Value=user@example.com \
  --temporary-password "TempPass123!"
```

## Cleanup

```bash
npm run destroy
```

## License

MIT
