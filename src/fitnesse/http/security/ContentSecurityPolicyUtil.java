// Copyright (C) 2025 - Released under the terms of the CPL Common Public License version 1.0.
package fitnesse.http.security;

import fitnesse.http.Response;

/**
 * Utility class for adding Content Security Policy (CSP) headers to HTTP responses.
 * Implements strict CSP to prevent XSS attacks by blocking inline scripts and unsafe content.
 */
public class ContentSecurityPolicyUtil {
    
    /**
     * Strict CSP policy that blocks inline scripts and restricts sources to same origin.
     * This policy prevents execution of inline event handlers like onerror, onload, etc.
     */
    public static final String STRICT_CSP_POLICY = 
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +  // Allow inline CSS for styling
        "img-src 'self' data:; " +               // Allow data URLs for inline images
        "font-src 'self'; " +
        "connect-src 'self'; " +
        "media-src 'self'; " +
        "object-src 'none'; " +                 // Block all plugins
        "frame-src 'none'; " +                  // Block frames
        "base-uri 'self'; " +                   // Restrict base tag
        "form-action 'self'";                   // Restrict form submissions
    
    /**
     * Relaxed CSP policy for test execution pages that need inline JavaScript.
     * Still maintains security by restricting sources to same origin and blocking dangerous elements.
     */
    public static final String TEST_EXECUTION_CSP_POLICY = 
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline'; " +  // Allow inline scripts for test functionality
        "style-src 'self' 'unsafe-inline'; " +   // Allow inline CSS for styling
        "img-src 'self' data:; " +               // Allow data URLs for inline images
        "font-src 'self'; " +
        "connect-src 'self'; " +
        "media-src 'self'; " +
        "object-src 'none'; " +                 // Block all plugins
        "frame-src 'none'; " +                  // Block frames
        "base-uri 'self'; " +                   // Restrict base tag
        "form-action 'self'";                   // Restrict form submissions
    
    /**
     * Adds Content Security Policy headers to the HTTP response.
     * This helps prevent XSS attacks by controlling which resources can be loaded.
     * 
     * @param response The HTTP response to add CSP headers to
     */
    public static void addContentSecurityPolicyHeaders(Response response) {
        addContentSecurityPolicyHeaders(response, false);
    }
    
    /**
     * Adds Content Security Policy headers to the HTTP response with optional relaxed policy for tests.
     * 
     * @param response The HTTP response to add CSP headers to
     * @param allowInlineScripts Whether to allow inline scripts (for test execution)
     */
    public static void addContentSecurityPolicyHeaders(Response response, boolean allowInlineScripts) {
        if (response == null) {
            return;
        }
        
        // Choose the appropriate CSP policy
        String cspPolicy = allowInlineScripts ? TEST_EXECUTION_CSP_POLICY : STRICT_CSP_POLICY;
        
        // Add the main CSP header
        response.addHeader("Content-Security-Policy", cspPolicy);
        
        // Add additional security headers that complement CSP
        addComplementarySecurityHeaders(response);
    }
    
    /**
     * Adds additional security headers that work together with CSP for comprehensive protection.
     * Note: For secure cookie handling, use SecureCookieUtil.setSecureCookie() which automatically
     * adds HttpOnly, Secure, and SameSite flags to prevent cookie theft attacks.
     * 
     * @param response The HTTP response to add security headers to
     */
    private static void addComplementarySecurityHeaders(Response response) {
        // Prevent MIME type sniffing
        response.addHeader("X-Content-Type-Options", "nosniff");
        
        // Enable XSS protection in browsers
        response.addHeader("X-XSS-Protection", "1; mode=block");
        
        // Prevent page from being embedded in frames (clickjacking protection)
        response.addHeader("X-Frame-Options", "DENY");
        
        // Only send referrer for same-origin requests
        response.addHeader("Referrer-Policy", "same-origin");
        
        // Note: Cookie security is handled by SecureCookieUtil, not here.
        // Always use SecureCookieUtil.setSecureCookie() for any authentication 
        // or session cookies to ensure HttpOnly, Secure, and SameSite flags are set.
    }
    
    /**
     * Checks if the response content type indicates HTML content that should have CSP headers.
     * 
     * @param response The HTTP response to check
     * @return true if CSP headers should be added, false otherwise
     */
    public static boolean shouldAddCSPHeaders(Response response) {
        if (response == null) {
            return false;
        }
        
        String contentType = response.getContentType();
        return contentType != null && 
               (contentType.contains("text/html") || 
                contentType.equals(Response.Format.HTML.getContentType()));
    }
    
    /**
     * Conditionally adds CSP headers only if the response is HTML content.
     * 
     * @param response The HTTP response to potentially add CSP headers to
     */
    public static void addCSPHeadersIfHtml(Response response) {
        if (shouldAddCSPHeaders(response)) {
            addContentSecurityPolicyHeaders(response);
        }
    }
}
