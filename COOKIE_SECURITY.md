# Cookie Security Implementation

## Overview

This document describes the secure cookie implementation added to FitNesse to prevent cookie theft attacks.

## Security Vulnerabilities Addressed

### 1. Cookie Theft via XSS (Cross-Site Scripting)
**Problem**: Without the `HttpOnly` flag, malicious JavaScript can access cookies via `document.cookie`
**Solution**: All cookies are now set with the `HttpOnly` flag

### 2. Cookie Theft via Man-in-the-Middle Attacks  
**Problem**: Without the `Secure` flag, cookies are transmitted over unencrypted HTTP
**Solution**: Production cookies are set with the `Secure` flag (HTTPS only)

### 3. CSRF (Cross-Site Request Forgery) Attacks
**Problem**: Without `SameSite` protection, cookies are sent with cross-origin requests
**Solution**: All cookies use `SameSite=Strict` policy

## Usage Examples

### Setting Secure Authentication Cookies
```java
// For HTTPS production environments
SecureCookieUtil.setSecureCookie(response, "authToken", "abc123", 3600, true);

// For HTTP development environments  
SecureCookieUtil.setSecureCookie(response, "authToken", "abc123", 3600, false);
```

### Setting Session Cookies
```java
// Session cookie (expires when browser closes)
SecureCookieUtil.setSecureSessionCookie(response, "sessionId", "xyz789", true);
```

### Deleting Cookies Securely
```java
// Delete with specific path
SecureCookieUtil.deleteCookie(response, "oldSession", "/admin");

// Delete with default path
SecureCookieUtil.deleteCookie(response, "oldSession");
```

### Custom Cookie Configuration
```java
SecureCookieUtil.setSecureCookie(
    response, 
    "userPrefs",           // name
    "theme=dark",          // value  
    86400,                 // maxAge (24 hours)
    "/admin",              // path
    true,                  // secure (HTTPS only)
    true,                  // httpOnly (no JS access)
    SameSitePolicy.LAX     // sameSite policy
);
```

## SameSite Policy Options

- **STRICT**: Most secure - cookie only sent with same-site requests
- **LAX**: Moderate - cookie sent with top-level navigation from external sites  
- **NONE**: Least secure - cookie sent with all cross-site requests (requires Secure flag)

## Security Headers Integration

The secure cookie implementation works alongside existing CSP (Content Security Policy) headers:

```java
// Apply comprehensive security
ContentSecurityPolicyUtil.addContentSecurityPolicyHeaders(response);
SecureCookieUtil.setSecureCookie(response, "auth", "token", 3600, true);
```

This provides defense-in-depth against:
- XSS attacks (CSP + HttpOnly cookies)
- CSRF attacks (SameSite cookies + CSP)
- Clickjacking (X-Frame-Options)
- MIME sniffing (X-Content-Type-Options)

## Migration Guidelines

### Before (Vulnerable)
```java
// OLD - INSECURE
response.addHeader("Set-Cookie", "sessionId=abc123");
```

### After (Secure)  
```java
// NEW - SECURE
SecureCookieUtil.setSecureCookie(response, "sessionId", "abc123", 3600, true);
```

## Environment-Specific Configuration

### Production (HTTPS)
- Use `secure = true` 
- Enables full security protection
- Cookies only transmitted over HTTPS

### Development (HTTP)
- Use `secure = false`
- Maintains HttpOnly and SameSite protection
- Allows local development over HTTP

## Testing

The implementation includes comprehensive tests:
- `SecureCookieUtilTest.java` - Unit tests for cookie utility
- `SecurityIntegrationTest.java` - Integration tests with CSP headers

## Attack Prevention Examples

### XSS Cookie Theft Prevention
```javascript
// This attack is blocked by HttpOnly flag:
document.cookie; // Cannot access HttpOnly cookies
```

### CSRF Attack Prevention  
```javascript
// This attack is blocked by SameSite=Strict:
// Malicious site cannot include cookies in cross-origin requests
fetch('https://fitnesse.example.com/admin/delete', {
    method: 'POST',
    credentials: 'include' // Cookie will NOT be sent due to SameSite=Strict
});
```

### MITM Attack Prevention
```
// This attack is blocked by Secure flag:
// Cookies marked Secure are never sent over HTTP connections
```

## Best Practices

1. **Always use SecureCookieUtil** instead of manually setting cookie headers
2. **Use secure=true in production** environments with HTTPS
3. **Use SameSite=Strict** for authentication cookies
4. **Use SameSite=Lax** only if you need cross-site navigation with cookies
5. **Set appropriate expiration times** - shorter is more secure
6. **Delete cookies properly** when sessions end
7. **Use session cookies** for temporary data
8. **Test security measures** in both HTTP and HTTPS environments
