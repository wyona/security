package org.wyona.security.core.api;

import org.apache.log4j.Logger;

/**
 * World or user with a name
 */
public class Identity implements java.io.Serializable {

    private static Logger log = Logger.getLogger(Identity.class);
    
    protected String username;
    protected String[] groupnames;
    private String alias;

    private java.util.HashMap customAttributes;

    private boolean isWorld = false;

    /**
     * Identity is WORLD
     */
    public Identity() {
        username = null;
        groupnames = null;
        isWorld = true;
    }

    /**
     *
     */
    public Identity(String username, String alias) {
        this.username = username;
        this.groupnames = null;
        this.alias = alias;
    }

    /**
     * Create new identity inside memory
     *
     * @param username User ID
     * @param groupnames List of group IDs of which the user is supposed to be member of
     * @param alias User alias, e.g. e-mail address
     */
    public Identity(String username, String[] groupnames, String alias) {
        this.username = username;
        this.alias = alias;
        // TODO: What about parents groups?! This method seems to be used a lot, e.g. during policy instantiation ...!
        //log.error("DEBUG: Set groupnames via String array for user: " + username);
        this.groupnames = groupnames;
    }
    
    /**
     *
     */
    public Identity(User user, String alias) {
        try {
            this.username = user.getID();
            this.alias = alias;

            log.info("Set groupnames via user object for user '" + user.getID() + "' such that also parent groups of groups are loaded!");
            boolean getAlsoParentsOfGroups = true; // NOTE: And their parents, etc.

            String[] groupIDs = user.getGroupIDs(getAlsoParentsOfGroups);
            if (groupIDs != null) {
                groupnames = new String[groupIDs.length];
                for (int i = 0; i < groupIDs.length; i++) {
                    groupnames[i] = groupIDs[i];
                }
            } else {
                log.warn("User/Identity '" + this.username + "' is not a member of any group!");
            }
        } catch (AccessManagementException e) {
            log.error(e, e);
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Get name of user (true name) or null for World
     */
    public String getUsername() {
        return username;
    }

    /**
     * Get pseudonym of user
     */
    public String getAlias() {
        return alias;
    }

/* WARNING: This method leads to problems re serialization within a clustered environment!
    public User getUser() {
        return user;
    }
*/
    
    /**
     * 
     */
    public String[] getGroupnames() {
        // For security reasons a copy instead the reference is being returned
        if (groupnames != null) {
            String[] copy = new String[groupnames.length];
            for (int i = 0; i < groupnames.length; i++) {
                copy[i] = groupnames[i];
            }
            return copy;
        } else {
            if (isWorld()) {
                log.debug("No groups for WORLD!");
            } else {
                log.warn("No groups for user '" + getUsername() + "'!");
            }
            return null;
        }
    }
    
    /**
     *
     */
    private void writeObject(java.io.ObjectOutputStream out) throws java.io.IOException {
        out.defaultWriteObject();
        // TODO: Does this actually make sense?!
        //out.defaultObject(username);
        //out.defaultObject(groupnames);
    }

    /**
     *
     */
    private void readObject(java.io.ObjectInputStream in) throws java.io.IOException, ClassNotFoundException {
        in.defaultReadObject();
        // TODO: Does this actually make sense?!
        //username = (String) in.readObject();
        //groupnames = (String[]) in.readObject();
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append("User ID: ");
        if (getUsername() == null) {
            sb.append("WORLD");
        } else {
            sb.append(getUsername());
        }

        sb.append(" - Groups: ");
        String[] gn = getGroupnames();
        if (gn != null) {
            for (int i = 0; i < gn.length; i++) {
                sb.append(gn[i]);
                if (i < gn.length - 1) {
                    sb.append(", ");
                }
            }
        }

        return sb.toString();
    }

    /**
     * Check whether this identity is world
     */
    public boolean isWorld() {
        return isWorld;
    }

    /**
     * Set custom attribute, e.g. some authentication constraint
     * @param name Attribute name/key
     * @param value Attribute value
     */
    public void setAttribute(String name, String value) {
        if (customAttributes == null) customAttributes = new java.util.HashMap();
        customAttributes.put(name, value);
    }

    /**
     * Get custom attribute
     * @param name Attribute name/key
     * @return Value of custom attribute and if no such attribute exists, then return null
     */
    public String getAttribute(String name) {
        if (customAttributes != null) {
            return (String) customAttributes.get(name);
        } else {
            log.debug("No custom attributes set yet!");
            return null;
        }
    }
}
