package org.wyona.security.core.api;

/**
 *
 */
public class Identity {

    protected String username;
    protected String[] groupnames;

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
