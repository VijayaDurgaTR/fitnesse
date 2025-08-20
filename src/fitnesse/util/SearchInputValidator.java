// Copyright (C) 2003-2009 by Object Mentor, Inc. All rights reserved.
// Released under the terms of the CPL Common Public License version 1.0.
package fitnesse.util;

import java.util.regex.Pattern;

/**
 * Utility class for validating and sanitizing search input strings to prevent
 * HTML/JavaScript injection attacks and ensure only safe characters are used.
 */
public class SearchInputValidator {
    
    // Allow alphanumeric characters, spaces, basic punctuation, and common search operators
    private static final Pattern ALLOWED_CHARACTERS = Pattern.compile("^[a-zA-Z0-9\\s\\-_\\.\\*\\?\\+\\(\\)\\[\\]\\{\\}\\|\\\\]+$");
    
    // Patterns to detect potentially dangerous content
    private static final Pattern HTML_TAGS = Pattern.compile("<[^>]*>");
    private static final Pattern JAVASCRIPT_EVENTS = Pattern.compile("(?i)on\\w+\\s*=[^\\s]*");
    private static final Pattern SCRIPT_TAGS = Pattern.compile("(?i)<\\s*/?\\s*script[^>]*>");
    private static final Pattern DANGEROUS_QUOTES = Pattern.compile("[\"'`]");
    private static final Pattern ANGLE_BRACKETS = Pattern.compile("[<>]");
    private static final Pattern JAVASCRIPT_PROTOCOL = Pattern.compile("(?i)javascript:");
    private static final Pattern PARENTHESES_CONTENT = Pattern.compile("\\([^)]*\\)");
    
    // Maximum allowed length for search strings
    private static final int MAX_SEARCH_LENGTH = 500;
    
    /**
     * Validates a search string using strict allowlist validation.
     * Only permits alphanumeric characters, spaces, and basic search operators.
     * 
     * @param searchString the input search string to validate
     * @return true if the search string is valid, false otherwise
     */
    public static boolean isValidSearchString(String searchString) {
        if (searchString == null) {
            return false;
        }
        
        // Check length
        if (searchString.length() > MAX_SEARCH_LENGTH) {
            return false;
        }
        
        // Empty strings are valid
        if (searchString.trim().isEmpty()) {
            return true;
        }
        
        // Check against allowlist pattern
        return ALLOWED_CHARACTERS.matcher(searchString).matches();
    }
    
    /**
     * Sanitizes a search string by removing or escaping dangerous characters.
     * This is a fallback for cases where rejection is not appropriate.
     * 
     * @param searchString the input search string to sanitize
     * @return a sanitized version of the search string
     */
    public static String sanitizeSearchString(String searchString) {
        if (searchString == null) {
            return "";
        }
        
        // Truncate if too long
        if (searchString.length() > MAX_SEARCH_LENGTH) {
            searchString = searchString.substring(0, MAX_SEARCH_LENGTH);
        }
        
        // Remove HTML tags (this also removes content between script tags)
        searchString = HTML_TAGS.matcher(searchString).replaceAll(" ");
        
        // Additional cleanup for script content that might remain
        searchString = searchString.replaceAll("(?i)alert\\s*", "");
        searchString = searchString.replaceAll("(?i)eval\\s*", "");
        searchString = searchString.replaceAll("(?i)function\\s*", "");
        
        // Remove JavaScript event handlers
        searchString = JAVASCRIPT_EVENTS.matcher(searchString).replaceAll("");
        
        // Remove JavaScript protocol
        searchString = JAVASCRIPT_PROTOCOL.matcher(searchString).replaceAll("");
        
        // Remove script tags
        searchString = SCRIPT_TAGS.matcher(searchString).replaceAll(" ");
        
        // Remove parentheses content (often contains function calls)
        searchString = PARENTHESES_CONTENT.matcher(searchString).replaceAll("");
        
        // Remove dangerous quotes
        searchString = DANGEROUS_QUOTES.matcher(searchString).replaceAll("");
        
        // Remove angle brackets
        searchString = ANGLE_BRACKETS.matcher(searchString).replaceAll("");
        
        // Keep only allowed characters
        StringBuilder sanitized = new StringBuilder();
        for (char c : searchString.toCharArray()) {
            if (isAllowedCharacter(c)) {
                sanitized.append(c);
            }
        }
        
        // Normalize multiple spaces to single spaces and trim
        String result = sanitized.toString().replaceAll("\\s+", " ").trim();
        
        return result;
    }
    
    /**
     * Checks if a character is allowed in search strings.
     * 
     * @param c the character to check
     * @return true if the character is allowed, false otherwise
     */
    private static boolean isAllowedCharacter(char c) {
        return Character.isLetterOrDigit(c) || 
               Character.isWhitespace(c) ||
               c == '-' || c == '_' || c == '.' ||
               c == '*' || c == '?' || c == '+' ||
               c == '(' || c == ')' || c == '[' || c == ']' ||
               c == '{' || c == '}' || c == '|' || c == '\\';
    }
    
    /**
     * Validates and sanitizes a search string, with preference for validation.
     * If validation fails, attempts sanitization as a fallback.
     * 
     * @param searchString the input search string
     * @return a valid search string, either the original (if valid) or sanitized version
     */
    public static String validateAndSanitize(String searchString) {
        if (isValidSearchString(searchString)) {
            return searchString;
        }
        return sanitizeSearchString(searchString);
    }
    
    /**
     * Gets the maximum allowed length for search strings.
     * 
     * @return the maximum allowed length
     */
    public static int getMaxSearchLength() {
        return MAX_SEARCH_LENGTH;
    }
}
