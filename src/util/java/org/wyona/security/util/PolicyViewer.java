package org.wyona.security.util;

import org.wyona.security.core.api.Policy;
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
            Policy p = pm.getPolicy(path);
            if (p != null) {
                return "<html><body>" + p.toString() + "</body></html>";
            } else {
                return "<html><body>No policy for path: " + path + "#"+contentItemId+"</body></html>";
            }
        } catch(Exception e) {
            return "<html><body>Exception: " + e.getMessage() + "</body></html>";
        }
    }
}
