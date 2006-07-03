package org.wyona.security.core.api;

/**
 *
 */
public class Identity {

    protected String username;
    protected String[] groupnames;

    /**
     * Identity is WORLD
     */
    public Identity() {
        username = null;
        groupnames = null;
    }

    /**
     *
     */
    public Identity(String username, String[] groupnames) {
        this.username = username;
        this.groupnames = groupnames;
    }

    /**
     *
     */
    public String getUsername() {
        return username;
    }

    /**
     *
     */
    public String[] getGroupnames() {
        return groupnames;
    }
}
