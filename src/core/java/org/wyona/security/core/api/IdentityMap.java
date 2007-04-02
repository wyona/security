package org.wyona.security.core.api;

import java.util.HashMap;
import java.util.Iterator;

import org.apache.log4j.Category;

/**
 *
 */
public class IdentityMap extends HashMap {

    private static Category log = Category.getInstance(Identity.class);
    
    public String toString() {
        StringBuffer buf = new StringBuffer();
        Iterator iter = this.keySet().iterator();
        while (iter.hasNext()) {
            Object key = iter.next();
            Object value = this.get(key);
            if (value instanceof Identity) {
                buf.append(((Identity)value).getUsername());
                buf.append(" (" + key + " realm)");
                if (iter.hasNext()) {
                    buf.append(", ");
                }
            }
        }
        return buf.toString();
    }
}
