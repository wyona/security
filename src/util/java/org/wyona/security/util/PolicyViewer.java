package org.wyona.security.util;

import org.wyona.security.core.AuthorizationException;
import org.wyona.security.core.UsecasePolicy;
import org.wyona.security.core.api.Identity;
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
            StringBuffer sb = new StringBuffer("<html><body>");
            sb.append("<p>Access Policies for Path <i>" + path + "#" + contentItemId + "</i>:</p>");
            sb.append("<p><table border=\"1\">");
            sb.append("<tr><td>Path</td>" + getSplittedPath(pm, path, contentItemId) + "</tr>");
            sb.append("<tr valign=\"top\"><td>Policy</td>" + getPolicies(pm, path, contentItemId) + "</tr>");
            sb.append("<tr valign=\"top\"><td>Aggregated Policy</td>" + getAggregatedPolicies(pm, path, contentItemId) + "</tr>");
            sb.append("</table></p>");
            sb.append("</body></html>");
            return sb.toString();
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

    /**
     * Get policies
     */
    static public StringBuffer getPolicies (PolicyManager pm, String path, String contentItemId) throws AuthorizationException {
        String[] names = path.split("/");
        StringBuffer sb = new StringBuffer();
        StringBuffer currentPath = new StringBuffer();
        for (int i = 0; i < names.length -1; i++) {
            currentPath.append(names[i] + "/");
            Policy p = pm.getPolicy(currentPath.toString());
            if (p != null) {
                sb.append("<td>" + getPolicyAsXHTMLList(p) + "</td>");
            } else {
                sb.append("<td>No policy yet!</td>");
            }
        }
        Policy p = pm.getPolicy(path);
        if (p != null) {
            sb.append("<td>" + getPolicyAsXHTMLList(p) + "</td>");
        } else {
            sb.append("<td>No policy yet!</td>");
        }
        if (contentItemId != null) {
            sb.append("<td>Not implemented yet into API!</td>");
        }
        return sb;
    }

    /**
     * Get aggregated policies
     */
    static public StringBuffer getAggregatedPolicies (PolicyManager pm, String path, String contentItemId) throws AuthorizationException {
        return getPolicies(pm, path, contentItemId);
    }

    /**
     * Get policy as XHTML list
     */
    static public StringBuffer getPolicyAsXHTMLList(Policy p) {
        StringBuffer sb = new StringBuffer();
        UsecasePolicy[] up = p.getUsecasePolicies();
        if (up != null && up.length > 0) {
            sb.append("<ul>");
            for (int i = 0; i < up.length; i++) {
                sb.append("<li>Usecase: " + up[i].getName());
                Identity[] ids = up[i].getIdentities();
                // TODO: check of ids.length > 0 or groups/hosts exists ...
                sb.append("<ol>");
                for (int j = 0; j < ids.length; j++) {
                    if (ids[j].isWorld()) {
                        sb.append("<li>WORLD</li>");
                    } else {
                        sb.append("<li>User: " + ids[j].getUsername() + "</li>");
                    }
                }
                sb.append("</ol>");
                sb.append("</li>");
            }
            sb.append("</ul>");
        } else {
            sb.append("No policy usecases!");
        }
        return sb;
    }
}
