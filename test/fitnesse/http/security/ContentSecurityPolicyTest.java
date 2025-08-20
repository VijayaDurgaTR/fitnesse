package fitnesse.http.security;

import fitnesse.http.Response;
import fitnesse.http.SimpleResponse;
import fitnesse.http.ChunkedResponse;
import fitnesse.testutil.FitNesseUtil;
import org.junit.Test;
import static org.junit.Assert.*;

public class ContentSecurityPolicyTest {

  @Test
  public void testCSPHeadersAddedToHtmlResponse() {
    SimpleResponse response = new SimpleResponse();
    response.setContentType("text/html");
    
    ContentSecurityPolicyUtil.addCSPHeadersIfHtml(response);
    
    // Check that CSP header is present
    String cspHeader = response.getHeader("Content-Security-Policy");
    assertNotNull("CSP header should be present", cspHeader);
    assertEquals("CSP header should have strict policy", 
                 ContentSecurityPolicyUtil.STRICT_CSP_POLICY, cspHeader);
                 
    // Check other security headers
    assertEquals("nosniff", response.getHeader("X-Content-Type-Options"));
    assertEquals("1; mode=block", response.getHeader("X-XSS-Protection"));
    assertEquals("DENY", response.getHeader("X-Frame-Options"));
    assertEquals("same-origin", response.getHeader("Referrer-Policy"));
  }

  @Test
  public void testCSPHeadersNotAddedToNonHtmlResponse() {
    SimpleResponse response = new SimpleResponse();
    response.setContentType("application/json");
    
    ContentSecurityPolicyUtil.addCSPHeadersIfHtml(response);
    
    // CSP header should not be added to non-HTML responses
    String cspHeader = response.getHeader("Content-Security-Policy");
    assertNull("CSP header should not be present for non-HTML content", cspHeader);
  }

  @Test 
  public void testCSPHeadersAddedToTextHtmlResponse() {
    SimpleResponse response = new SimpleResponse();
    response.setContentType("text/html; charset=utf-8");
    
    ContentSecurityPolicyUtil.addCSPHeadersIfHtml(response);
    
    String cspHeader = response.getHeader("Content-Security-Policy");
    assertNotNull("CSP header should be present for text/html with charset", cspHeader);
  }

  @Test
  public void testCSPHeadersAddedToChunkedResponse() {
    // Create a mock ChunkedDataProvider
    MockChunkedDataProvider provider = new MockChunkedDataProvider();
    ChunkedResponse response = new ChunkedResponse("html", provider);
    
    ContentSecurityPolicyUtil.addCSPHeadersIfHtml(response);
    
    String cspHeader = response.getHeader("Content-Security-Policy");
    assertNotNull("CSP header should be present for chunked HTML response", cspHeader);
    assertEquals("CSP header should have strict policy", 
                 ContentSecurityPolicyUtil.STRICT_CSP_POLICY, cspHeader);
  }

  @Test
  public void testStrictCSPPolicyBlocksInlineScripts() {
    String policy = ContentSecurityPolicyUtil.STRICT_CSP_POLICY;
    
    // Verify that the policy restricts dangerous sources
    assertTrue("Policy should specify default-src 'self'", 
               policy.contains("default-src 'self'"));
    assertTrue("Policy should specify script-src 'self'", 
               policy.contains("script-src 'self'"));
    assertTrue("Policy should specify object-src 'none'", 
               policy.contains("object-src 'none'"));
    
    // Verify that unsafe inline scripts are not allowed (only styles are allowed for CSS)
    assertFalse("Policy should not allow 'unsafe-eval' for scripts", 
                policy.contains("'unsafe-eval'"));
    
    // Style-src may contain 'unsafe-inline' for CSS, but script-src should not
    String scriptSrc = extractDirectiveValue(policy, "script-src");
    assertFalse("script-src should not allow 'unsafe-inline'", 
                scriptSrc.contains("'unsafe-inline'"));
  }
  
  private String extractDirectiveValue(String policy, String directive) {
    String[] parts = policy.split(";");
    for (String part : parts) {
      part = part.trim();
      if (part.startsWith(directive)) {
        return part.substring(directive.length()).trim();
      }
    }
    return "";
  }

  // Mock ChunkedDataProvider for testing
  private static class MockChunkedDataProvider implements fitnesse.http.ChunkedDataProvider {
    @Override
    public void startSending() {
      // Mock implementation - no actual sending needed for test
    }
  }
}
