package org.wyona.security.util;

import org.wyona.security.core.api.PolicyManager;

/**
 * Utility class to view policies
 */
public class PolicyViewer {

    /**
     * Get XHTML view of policies
     */
    static public String getXHTMLView (PolicyManager pm, String path, String contentItemId) {
        try {
            return pm.getPolicy(path).toString();
        } catch(Exception e) {
            return "<html><body>Exception: " + e.getMessage() + "</body></html>";
        }
    }
}
