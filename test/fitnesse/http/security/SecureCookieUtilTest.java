// Copyright (C) 2025 - Released under the terms of the CPL Common Public License version 1.0.
package fitnesse.http.security;

import fitnesse.http.SimpleResponse;
import org.junit.Before;
import org.junit.Test;

import static fitnesse.http.security.SecureCookieUtil.SameSitePolicy;
import static org.junit.Assert.*;

/**
 * Tests for SecureCookieUtil to ensure proper cookie security flags are set.
 */
public class SecureCookieUtilTest {
    
    private SimpleResponse response;
    
    @Before
    public void setUp() {
        response = new SimpleResponse();
    }
    
    @Test
    public void testSetSecureCookieWithAllFlags() {
        SecureCookieUtil.setSecureCookie(response, "sessionId", "abc123", 3600, true);
        
        String cookieHeader = response.getHeader("Set-Cookie");
        assertNotNull("Cookie header should be set", cookieHeader);
        
        // Verify all security flags are present
        assertTrue("Should contain cookie name and value", cookieHeader.contains("sessionId=abc123"));
        assertTrue("Should contain Max-Age", cookieHeader.contains("Max-Age=3600"));
        assertTrue("Should contain Path", cookieHeader.contains("Path=/"));
        assertTrue("Should contain Secure flag", cookieHeader.contains("Secure"));
        assertTrue("Should contain HttpOnly flag", cookieHeader.contains("HttpOnly"));
        assertTrue("Should contain SameSite=Strict", cookieHeader.contains("SameSite=Strict"));
    }
    
    @Test
    public void testSetSecureCookieCustomPath() {
        SecureCookieUtil.setSecureCookie(response, "userPref", "theme=dark", 86400, 
                                       "/admin", true, true, SameSitePolicy.LAX);
        
        String cookieHeader = response.getHeader("Set-Cookie");
        assertTrue("Should contain custom path", cookieHeader.contains("Path=/admin"));
        assertTrue("Should contain SameSite=Lax", cookieHeader.contains("SameSite=Lax"));
    }
    
    @Test
    public void testSetSecureSessionCookie() {
        SecureCookieUtil.setSecureSessionCookie(response, "tempSession", "xyz789", true);
        
        String cookieHeader = response.getHeader("Set-Cookie");
        assertNotNull("Cookie header should be set", cookieHeader);
        
        // Session cookies should not have Max-Age
        assertFalse("Session cookie should not have Max-Age", cookieHeader.contains("Max-Age"));
        assertTrue("Should contain Secure flag", cookieHeader.contains("Secure"));
        assertTrue("Should contain HttpOnly flag", cookieHeader.contains("HttpOnly"));
        assertTrue("Should contain SameSite=Strict", cookieHeader.contains("SameSite=Strict"));
    }
    
    @Test
    public void testSetInsecureCookieForLocalDevelopment() {
        SecureCookieUtil.setSecureCookie(response, "devCookie", "value", 3600, false);
        
        String cookieHeader = response.getHeader("Set-Cookie");
        assertNotNull("Cookie header should be set", cookieHeader);
        
        // For local development (HTTP), Secure flag should not be present
        assertFalse("Should not contain Secure flag for HTTP", cookieHeader.contains("Secure"));
        assertTrue("Should still contain HttpOnly flag", cookieHeader.contains("HttpOnly"));
        assertTrue("Should still contain SameSite=Strict", cookieHeader.contains("SameSite=Strict"));
    }
    
    @Test
    public void testDeleteCookie() {
        SecureCookieUtil.deleteCookie(response, "oldCookie", "/admin");
        
        String cookieHeader = response.getHeader("Set-Cookie");
        assertNotNull("Cookie header should be set", cookieHeader);
        
        assertTrue("Should set cookie value to empty", cookieHeader.contains("oldCookie="));
        assertTrue("Should set Max-Age to 0", cookieHeader.contains("Max-Age=0"));
        assertTrue("Should contain custom path", cookieHeader.contains("Path=/admin"));
    }
    
    @Test
    public void testDeleteCookieDefaultPath() {
        SecureCookieUtil.deleteCookie(response, "sessionCookie");
        
        String cookieHeader = response.getHeader("Set-Cookie");
        assertTrue("Should use default path", cookieHeader.contains("Path=/"));
        assertTrue("Should set Max-Age to 0", cookieHeader.contains("Max-Age=0"));
    }
    
    @Test
    public void testSameSitePolicyValues() {
        assertEquals("Strict", SameSitePolicy.STRICT.getValue());
        assertEquals("Lax", SameSitePolicy.LAX.getValue());
        assertEquals("None", SameSitePolicy.NONE.getValue());
    }
    
    @Test
    public void testNullSafetyForResponse() {
        // Should not throw exception with null response
        SecureCookieUtil.setSecureCookie(null, "test", "value", 3600, true);
        // No assertion needed - just ensuring no exception is thrown
    }
    
    @Test
    public void testNullSafetyForCookieName() {
        // Should not throw exception with null cookie name
        SecureCookieUtil.setSecureCookie(response, null, "value", 3600, true);
        
        String cookieHeader = response.getHeader("Set-Cookie");
        assertNull("Cookie header should not be set with null name", cookieHeader);
    }
    
    @Test
    public void testNullCookieValue() {
        SecureCookieUtil.setSecureCookie(response, "emptyCookie", null, 3600, true);
        
        String cookieHeader = response.getHeader("Set-Cookie");
        assertTrue("Should handle null value gracefully", cookieHeader.contains("emptyCookie="));
    }
    
    @Test
    public void testCookieValueWithSpecialCharacters() {
        // Test that cookie values are handled properly (in a real implementation, 
        // we might want to add URL encoding for special characters)
        SecureCookieUtil.setSecureCookie(response, "specialCookie", "value with spaces", 3600, true);
        
        String cookieHeader = response.getHeader("Set-Cookie");
        assertTrue("Should contain the cookie value", cookieHeader.contains("value with spaces"));
    }
    
    @Test 
    public void testCookieSecurityFlagsPreventCommonAttacks() {
        // Test that our cookie configuration prevents common attack vectors
        SecureCookieUtil.setSecureCookie(response, "authToken", "sensitive-token", 3600, true);
        
        String cookieHeader = response.getHeader("Set-Cookie");
        
        // HttpOnly prevents XSS attacks via document.cookie
        assertTrue("HttpOnly prevents JavaScript access", cookieHeader.contains("HttpOnly"));
        
        // Secure ensures cookie is only sent over HTTPS
        assertTrue("Secure prevents transmission over HTTP", cookieHeader.contains("Secure"));
        
        // SameSite=Strict prevents CSRF attacks
        assertTrue("SameSite=Strict prevents CSRF", cookieHeader.contains("SameSite=Strict"));
    }
}
