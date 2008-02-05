package org.wyona.security.util;

import org.wyona.security.core.AuthorizationException;
import org.wyona.security.core.UsecasePolicy;
import org.wyona.security.core.api.Identity;
import org.wyona.security.core.api.Policy;
import org.wyona.security.core.api.PolicyManager;

import org.apache.log4j.Logger;

/**
 * Utility class to view policies
 */
public class PolicyViewer {

    private static Logger log = Logger.getLogger(PolicyViewer.class);

    /**
     * Get XHTML view of policies
     */
    static public String getXHTMLView (PolicyManager pm, String path, String contentItemId) {
        try {
            StringBuffer sb = new StringBuffer("<html><body>");
            sb.append("<p>Access Policies for Path <i>" + path + "#" + contentItemId + "</i>:</p>");
            sb.append("<p><table border=\"1\">");
            sb.append("<tr><td>Path</td>" + getSplittedPath(pm, path, contentItemId) + "</tr>");
            sb.append("<tr valign=\"top\"><td>Policy</td>" + getPolicies(pm, path, contentItemId, false) + "</tr>");
            sb.append("<tr valign=\"top\"><td>Aggregated Policy</td>" + getPolicies(pm, path, contentItemId, true) + "</tr>");
            sb.append("</table></p>");
            sb.append("</body></html>");
            return sb.toString();
        } catch(Exception e) {
            log.error(e, e);
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
	log.error("DEBUG: Length: " + names.length);
	//log.debug("Length: " + names.length);
        if (path.endsWith("/")) {
            if (names.length > 0) {
                sb.append("<td>" + names[names.length -1] + "/</td>");
            } else {
                sb.append("<td>/</td>");
            }
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
    static public StringBuffer getPolicies (PolicyManager pm, String path, String contentItemId, boolean aggregated) throws AuthorizationException {
        String[] names = path.split("/");
        StringBuffer sb = new StringBuffer();
        StringBuffer currentPath = new StringBuffer();
        for (int i = 0; i < names.length -1; i++) {
            currentPath.append(names[i] + "/");
            Policy p = pm.getPolicy(currentPath.toString(), aggregated);
            if (p != null) {
                //sb.append("<td>" + getPolicyAsXHTMLListOrderedByUsecases(p) + "</td>");
                sb.append("<td>" + getPolicyAsXHTMLListOrderedByIdentities(p) + "</td>");
            } else {
                sb.append("<td>No policy yet!</td>");
            }
        }
        Policy p = pm.getPolicy(path, aggregated);
        if (p != null) {
            //sb.append("<td>" + getPolicyAsXHTMLListOrderedByUsecases(p) + "</td>");
            sb.append("<td>" + getPolicyAsXHTMLListOrderedByIdentities(p) + "</td>");
        } else {
            sb.append("<td>No policy yet!</td>");
        }
        if (contentItemId != null) {
            sb.append("<td>Not implemented yet into API!</td>");
        }
        return sb;
    }

    /**
     * Get policy as XHTML list ordered by usecases
     */
    static public StringBuffer getPolicyAsXHTMLListOrderedByUsecases(Policy p) {
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

    /**
     * Get policy as XHTML list ordered by identities
     */
    static public StringBuffer getPolicyAsXHTMLListOrderedByIdentities(Policy p) {
        StringBuffer sb = new StringBuffer();
        UsecasePolicy[] up = p.getUsecasePolicies();
        if (up != null && up.length > 0) {
            sb.append("<ul>");
            for (int i = 0; i < up.length; i++) {
                sb.append("<li>Usecase: " + up[i].getName());

/*
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
*/
            }
            sb.append("</ul>");
        } else {
            sb.append("No policy usecases!");
        }
        return sb;
    }
}
