// Copyright (C) 2003-2009 by Object Mentor, Inc. All rights reserved.
// Released under the terms of the CPL Common Public License version 1.0.
package fitnesse.html;

import fitnesse.FitNesseContext;
import fitnesse.html.template.HtmlPage;
import fitnesse.reporting.JavascriptUtil;
import fitnesse.responders.WikiPageActions;
import fitnesse.testutil.FitNesseUtil;
import fitnesse.wiki.PathParser;
import fitnesse.wiki.WikiPageUtil;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static util.RegexTestCase.assertSubString;

public class HtmlUtilTest {

  private FitNesseContext context;

  @Before
  public void setUp() {
    context = FitNesseUtil.makeTestContext();
  }

  @Test
  public void testMakeDivTag() {
    String expected = "<div class=\"myClass\"></div>" + HtmlElement.endl;
    HtmlTag div = new HtmlTag("div");
    div.addAttribute("class", "myClass");
    div.add("");
    assertEquals(expected, div.html());
  }

  @Test
  public void testMakeDefaultActions() {
    String pageName = "SomePage";
    String html = getActionsHtml(pageName);
    verifyDefaultLinks(html, "SomePage");
  }

  @Test
  public void testMakeActionsWithTestButtonWhenNameStartsWithTest() {
    String pageName = "TestSomething";
    String html = getActionsHtml(pageName);
    verifyDefaultLinks(html, pageName);
    assertSubString("<a class=\"nav-link text-secondary\" href=\"" + pageName + "?test\" accesskey=\"t\">Test</a>", html);
  }

  @Test
  public void testMakeActionsWithSuffixButtonWhenNameEndsWithTest() {
    String pageName = "SomethingTest";
    String html = getActionsHtml(pageName);
    verifyDefaultLinks(html, pageName);
    assertSubString("<a class=\"nav-link text-secondary\" href=\"" + pageName + "?test\" accesskey=\"t\">Test</a>", html);
  }

  @Test
  public void testMakeActionsWithSuiteButtonWhenNameStartsWithSuite() {
    String pageName = "SuiteNothings";
    String html = getActionsHtml(pageName);
    verifyDefaultLinks(html, pageName);
    assertSubString("<a class=\"nav-link text-secondary\" href=\"" + pageName + "?suite\" accesskey=\"t\">Suite</a>", html);
  }

  @Test
  public void testMakeActionsWithSuiteButtonWhenNameEndsWithSuite() {
    String pageName = "NothingsSuite";
    String html = getActionsHtml(pageName);
    verifyDefaultLinks(html, pageName);
    assertSubString("<a class=\"nav-link text-secondary\" href=\"" + pageName + "?suite\" accesskey=\"t\">Suite</a>", html);
  }

  @Test
  public void shouldEscapeOnlyXmlCharacters() {
    assertEquals("ab&amp;cd&lt;ef&gt;", HtmlUtil.escapeHTML("ab&cd<ef>"));
  }

  @Test
  public void shouldEscapeMultipleOccurencesOfTheSameCharacter() {
    assertEquals("ab&amp;cd&amp;ef&amp;", HtmlUtil.escapeHTML("ab&cd&ef&"));
  }

  @Test
  public void shouldUnescape() {
    assertEquals("& < > &lt; &gt; &amp;", HtmlUtil.unescapeHTML("&amp; &lt; &gt; &amp;lt; &amp;gt; &amp;amp;"));
  }

  private String getActionsHtml(String pageName) {
    WikiPageUtil.addPage(context.getRootPage(), PathParser.parse(pageName), "");
    HtmlPage htmlPage = context.pageFactory.newPage();
    htmlPage.setNavTemplate("wikiNav.vm");
    htmlPage.put("actions", new WikiPageActions(context.getRootPage().getChildPage(pageName)));
    return htmlPage.html(null);
  }

  private void verifyDefaultLinks(String html, String pageName) {
    assertSubString("<a class=\"nav-link text-secondary\" href=\"" + pageName + "?edit\" accesskey=\"e\">Edit</a>", html);
    assertSubString("<a class=\"dropdown-item\" href=\"" + pageName + "?versions\" accesskey=\"v\">Versions</a>", html);
    assertSubString("<a class=\"dropdown-item\" href=\"" + pageName + "?properties\" accesskey=\"p\">Properties</a>", html);
    assertSubString("<a class=\"dropdown-item\" href=\"" + pageName + "?refactor&amp;type=rename\">Rename</a>", html);
    assertSubString("<a class=\"dropdown-item\" href=\"" + pageName + "?whereUsed\" accesskey=\"w\">Where Used</a>", html);
    assertSubString("<a class=\"dropdown-item\" href=\"/files\" accesskey=\"f\">Files</a>", html);
    assertSubString("<a class=\"dropdown-item\" href=\"?search\" accesskey=\"s\">Search</a>", html);
    assertSubString("<a class=\"dropdown-item\" href=\"/FitNesse.UserGuide\" accesskey=\"\">User Guide</a>", html);
  }

  @Test
  public void testMakeReplaceElementScript() {
    String newText = "<p>My string has \"quotes\" and \r \n</p>";
    HtmlTag scriptTag = JavascriptUtil.makeReplaceElementScript("element-name", newText);
    String expected = "<script>document.getElementById(\"element-name\").innerHTML = " +
    		"\"<p>My string has \\\"quotes\\\" and \\r \\n</p>\";</script>";
    assertSubString(expected, scriptTag.html());
  }

  @Test
  public void testMakeInitErrorMetadataScript() {
    HtmlTag scriptTag = JavascriptUtil.makeInitErrorMetadataScript();
    String expected = "<script>initErrorMetadata();</script>";
    assertSubString(expected, scriptTag.html());
  }

  @Test
  public void testMakeAppendElementScript() {
    String appendText = "<p>My string has \"quotes\" and \r \n</p>";
    HtmlTag scriptTag = JavascriptUtil.makeAppendElementScript("element-name", appendText);
    String expected1 = "<script>var existingContent = document.getElementById(\"element-name\").innerHTML;";
    String expected2 = "document.getElementById(\"element-name\").innerHTML = " +
      "existingContent + \"<p>My string has \\\"quotes\\\" and \\r \\n</p>\";";
    String expected3 =  "</script>";
    assertSubString(expected1, scriptTag.html());
    assertSubString(expected2, scriptTag.html());
    assertSubString(expected3, scriptTag.html());
  }

  @Test
  public void shouldEscapeBackslashesInMakeAppendElementScript() {
    String appendText = "<p>My string has escaped \\r \\n</p>";
    HtmlTag scriptTag = JavascriptUtil.makeAppendElementScript("element\\r\\n\\", appendText);
    assertSubString("element\\\\r\\\\n\\\\", scriptTag.html());
    assertSubString("My string has escaped \\\\r \\\\n", scriptTag.html());
  }


  @Test
  public void shouldEscapeBackslashesInMakeReplaceElementScript() {
    String appendText = "<p>My string has escaped \\r \\n</p>";
    HtmlTag scriptTag = JavascriptUtil.makeReplaceElementScript("element\\r\\n\\", appendText);
    assertSubString("element\\\\r\\\\n\\\\", scriptTag.html());
    assertSubString("My string has escaped \\\\r \\\\n", scriptTag.html());
  }

  @Test
  public void testMakeSilentLink() {
    HtmlTag tag = JavascriptUtil.makeSilentLink("test?responder", new RawHtml("string with \"quotes\""));
    assertSubString("<a href=\"#\" onclick=\"doSilentRequest('test?responder')\">string with \"quotes\"</a>", tag.html());
  }

  @Test
  public void testEscapeHTML() {
    assertEquals("&amp;", HtmlUtil.escapeHTML("&"));
    assertEquals("&lt;", HtmlUtil.escapeHTML("<"));
    assertEquals("&gt;", HtmlUtil.escapeHTML(">"));
    assertEquals("&amp;&lt;&gt;", HtmlUtil.escapeHTML("&<>"));
    
    // Quotes should NOT be escaped in HTML content context
    assertEquals("\"", HtmlUtil.escapeHTML("\""));
    assertEquals("'", HtmlUtil.escapeHTML("'"));
  }

  @Test
  public void testEscapeHTMLAttribute() {
    assertEquals("&amp;", HtmlUtil.escapeHTMLAttribute("&"));
    assertEquals("&lt;", HtmlUtil.escapeHTMLAttribute("<"));
    assertEquals("&gt;", HtmlUtil.escapeHTMLAttribute(">"));
    assertEquals("&quot;", HtmlUtil.escapeHTMLAttribute("\""));
    assertEquals("&#x27;", HtmlUtil.escapeHTMLAttribute("'"));
    
    // Complete XSS test case
    assertEquals("&amp;&lt;&gt;&quot;&#x27;", HtmlUtil.escapeHTMLAttribute("&<>\"'"));
  }

  @Test
  public void testHTMLAttributeInjectionPrevention() {
    // Test cases that could be used for HTML attribute injection
    String maliciousInput1 = "value\" onload=\"alert('XSS')";
    String expected1 = "value&quot; onload=&quot;alert(&#x27;XSS&#x27;)";
    assertEquals(expected1, HtmlUtil.escapeHTMLAttribute(maliciousInput1));
    
    String maliciousInput2 = "value' onmouseover='alert(\"XSS\")'";
    String expected2 = "value&#x27; onmouseover=&#x27;alert(&quot;XSS&quot;)&#x27;";
    assertEquals(expected2, HtmlUtil.escapeHTMLAttribute(maliciousInput2));
    
    String maliciousInput3 = "<script>alert('XSS')</script>";
    String expected3 = "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;";
    assertEquals(expected3, HtmlUtil.escapeHTMLAttribute(maliciousInput3));
  }

  @Test
  public void testHTMLAttributeEscapeNullHandling() {
    assertEquals("", HtmlUtil.escapeHTMLAttribute(""));
    
    // Test null handling - should return null like the existing escapeHTML
    assertNull(HtmlUtil.escapeHTMLAttribute(null));
    
    String validText = "Hello World 123";
    assertEquals(validText, HtmlUtil.escapeHTMLAttribute(validText));
  }
}
