// Copyright (C) 2025 - Released under the terms of the CPL Common Public License version 1.0.
package fitnesse.http.security;

import fitnesse.http.Response;

/**
 * Utility class for creating secure cookies with proper security flags.
 * This helps prevent cookie theft attacks by setting HttpOnly, Secure, and SameSite flags.
 */
public class SecureCookieUtil {
    
    /**
     * Sets a secure cookie with all security flags enabled.
     * 
     * @param response The HTTP response to add the cookie to
     * @param name Cookie name
     * @param value Cookie value
     * @param maxAge Maximum age in seconds (0 = delete, -1 = session cookie)
     * @param secure Whether to require HTTPS for this cookie
     */
    public static void setSecureCookie(Response response, String name, String value, int maxAge, boolean secure) {
        setSecureCookie(response, name, value, maxAge, "/", secure, true, SameSitePolicy.STRICT);
    }
    
    /**
     * Sets a secure cookie with all security flags and custom path.
     * 
     * @param response The HTTP response to add the cookie to
     * @param name Cookie name
     * @param value Cookie value
     * @param maxAge Maximum age in seconds (0 = delete, -1 = session cookie)
     * @param path Cookie path
     * @param secure Whether to require HTTPS for this cookie
     * @param httpOnly Whether to prevent JavaScript access to this cookie
     * @param sameSite SameSite policy for CSRF protection
     */
    public static void setSecureCookie(Response response, String name, String value, int maxAge, 
                                     String path, boolean secure, boolean httpOnly, SameSitePolicy sameSite) {
        if (response == null || name == null) {
            return;
        }
        
        StringBuilder cookieBuilder = new StringBuilder();
        cookieBuilder.append(name).append("=").append(value != null ? value : "");
        
        // Add Max-Age for cookie expiration
        if (maxAge >= 0) {
            cookieBuilder.append("; Max-Age=").append(maxAge);
        }
        
        // Add Path
        if (path != null && !path.isEmpty()) {
            cookieBuilder.append("; Path=").append(path);
        }
        
        // Add Secure flag (cookie only sent over HTTPS)
        if (secure) {
            cookieBuilder.append("; Secure");
        }
        
        // Add HttpOnly flag (prevents XSS cookie theft via JavaScript)
        if (httpOnly) {
            cookieBuilder.append("; HttpOnly");
        }
        
        // Add SameSite flag (CSRF protection)
        if (sameSite != null) {
            cookieBuilder.append("; SameSite=").append(sameSite.getValue());
        }
        
        response.addHeader("Set-Cookie", cookieBuilder.toString());
    }
    
    /**
     * Sets a session cookie (no Max-Age) with security flags.
     * 
     * @param response The HTTP response to add the cookie to
     * @param name Cookie name
     * @param value Cookie value
     * @param secure Whether to require HTTPS for this cookie
     */
    public static void setSecureSessionCookie(Response response, String name, String value, boolean secure) {
        setSecureCookie(response, name, value, -1, "/", secure, true, SameSitePolicy.STRICT);
    }
    
    /**
     * Deletes a cookie by setting its value to empty and Max-Age to 0.
     * 
     * @param response The HTTP response to add the deletion cookie to
     * @param name Cookie name to delete
     * @param path Cookie path (must match the original cookie path)
     */
    public static void deleteCookie(Response response, String name, String path) {
        setSecureCookie(response, name, "", 0, path, false, true, SameSitePolicy.STRICT);
    }
    
    /**
     * Deletes a cookie with default path "/".
     * 
     * @param response The HTTP response to add the deletion cookie to
     * @param name Cookie name to delete
     */
    public static void deleteCookie(Response response, String name) {
        deleteCookie(response, name, "/");
    }
    
    /**
     * Enum for SameSite cookie policy values.
     */
    public enum SameSitePolicy {
        STRICT("Strict"),    // Most secure: cookie only sent with same-site requests
        LAX("Lax"),         // Moderate: cookie sent with top-level navigation from external sites
        NONE("None");       // Least secure: cookie sent with all cross-site requests (requires Secure flag)
        
        private final String value;
        
        SameSitePolicy(String value) {
            this.value = value;
        }
        
        public String getValue() {
            return value;
        }
    }
}
