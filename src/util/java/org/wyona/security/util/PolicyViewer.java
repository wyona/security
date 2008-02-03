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
                StringBuffer sb = new StringBuffer("<html><body>");
                sb.append("<p>Access Policies for Path <i>" + path + "#" + contentItemId + "</i>:</p>");
                sb.append("<p><table border=\"1\">");
                sb.append("<tr><td>Path</td>" + getSplittedPath(pm, path, contentItemId) + "</tr>");
                sb.append("<tr><td>Policy</td>" + getSplittedPath(pm, path, contentItemId) + "</tr>");
                sb.append("<tr><td>Aggregated Policy</td>" + getSplittedPath(pm, path, contentItemId) + "</tr>");
                sb.append("</table></p>");
                //sb.append(p.toString());
                sb.append("</body></html>");
                return sb.toString();
            } else {
                return "<html><body>No policy for path: " + path + "#"+contentItemId+"</body></html>";
            }
        } catch(Exception e) {
            return "<html><body>Exception: " + e.getMessage() + "</body></html>";
        }
    }

    /**
     * Get splitted path
     */
    static public StringBuffer getSplittedPath (PolicyManager pm, String path, String contentItemId) {
        String[] names = path.split("/");
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < names.length -1; i++) {
            sb.append("<td>" + names[i] + "/</td>");
        }
        if (path.endsWith("/")) {
            sb.append("<td>" + names[names.length -1] + "/</td>");
        } else {
            sb.append("<td>" + names[names.length -1] + "</td>");
        }
        if (contentItemId != null) {
            sb.append("<td>#" + contentItemId + "</td>");
        }
        return sb;
    }
}
