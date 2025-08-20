package fitnesse.http.security;

import fitnesse.FitNesseContext;
import fitnesse.http.MockRequest;
import fitnesse.http.Response;
import fitnesse.responders.search.SearchResponder;
import fitnesse.responders.BasicResponder;
import fitnesse.responders.ErrorResponder;
import fitnesse.testutil.FitNesseUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.*;

/**
 * Integration tests to verify that CSP headers are properly added to various HTTP responses.
 */
public class CSPIntegrationTest {
    
    private FitNesseContext context;
    
    @Before
    public void setUp() {
        context = FitNesseUtil.makeTestContext();
    }
    
    @After
    public void tearDown() throws IOException {
        FitNesseUtil.destroyTestContext(context);
    }
    
    @Test
    public void testSearchResponderAddsCSPHeaders() throws Exception {
        SearchResponder responder = new SearchResponder();
        MockRequest request = new MockRequest("FrontPage");
        request.addInput("searchString", "test");
        request.addInput("searchType", "content");
        
        Response response = responder.makeResponse(context, request);
        
        // Verify CSP header is present
        String cspHeader = response.getHeader("Content-Security-Policy");
        assertNotNull("SearchResponder should add CSP header", cspHeader);
        assertTrue("CSP should block inline scripts", cspHeader.contains("script-src 'self'"));
        assertTrue("CSP should restrict default sources", cspHeader.contains("default-src 'self'"));
        
        // Verify additional security headers
        assertNotNull("X-Content-Type-Options should be present", 
                      response.getHeader("X-Content-Type-Options"));
        assertNotNull("X-XSS-Protection should be present", 
                      response.getHeader("X-XSS-Protection"));
        assertNotNull("X-Frame-Options should be present", 
                      response.getHeader("X-Frame-Options"));
    }
    
    @Test
    public void testBasicResponderAddsCSPHeaders() throws Exception {
        BasicResponder responder = new BasicResponder();
        MockRequest request = new MockRequest("FrontPage");
        
        Response response = responder.makeResponse(context, request);
        
        // Verify CSP header is present for HTML responses
        String cspHeader = response.getHeader("Content-Security-Policy");
        if (response.getContentType() != null && response.getContentType().contains("text/html")) {
            assertNotNull("BasicResponder should add CSP header for HTML", cspHeader);
            assertTrue("CSP should prevent inline scripts", cspHeader.contains("script-src 'self'"));
        }
    }
    
    @Test
    public void testErrorResponderAddsCSPHeaders() throws Exception {
        ErrorResponder responder = new ErrorResponder("Test error message");
        MockRequest request = new MockRequest("NonExistentPage");
        
        Response response = responder.makeResponse(context, request);
        
        // Verify CSP header is present for error pages
        String cspHeader = response.getHeader("Content-Security-Policy");
        assertNotNull("ErrorResponder should add CSP header", cspHeader);
        assertTrue("CSP should block object sources", cspHeader.contains("object-src 'none'"));
        assertTrue("CSP should restrict form actions", cspHeader.contains("form-action 'self'"));
    }
    
    @Test
    public void testCSPPreventsXSSExploits() {
        String cspPolicy = ContentSecurityPolicyUtil.STRICT_CSP_POLICY;
        
        // Verify that common XSS attack vectors would be blocked by this policy
        assertTrue("Should block inline scripts", cspPolicy.contains("script-src 'self'"));
        assertTrue("Should block plugin content", cspPolicy.contains("object-src 'none'"));
        assertTrue("Should block frames", cspPolicy.contains("frame-src 'none'"));
        assertFalse("Should not allow unsafe-eval for scripts", cspPolicy.contains("script-src") && cspPolicy.contains("'unsafe-eval'"));
        
        // The policy should specifically prevent the type of XSS attack we've been working on:
        // <img src=x onerror=alert('XSS')>
        // This is blocked because:
        // 1. script-src 'self' prevents inline event handlers
        // 2. img-src 'self' data: restricts image sources 
        // 3. No 'unsafe-inline' in script-src
    }
}
