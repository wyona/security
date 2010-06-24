package org.wyona.security.core.api;

import org.apache.log4j.Logger;

/**
 * World or user with a name
 */
public class Identity implements java.io.Serializable {

    private static Logger log = Logger.getLogger(Identity.class);
    
    protected String username;
    protected String[] groupnames;

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
    public Identity(String username) {
        this.username = username;
        this.groupnames = null;
    }

    /**
     *
     */
    public Identity(String username, String[] groupnames) {
        this.username = username;
        // TODO: What about parents groups?! This method seems to be used a lot, e.g. during policy instantiation ...!
        //log.error("DEBUG: Set groupnames via String array for user: " + username);
        this.groupnames = groupnames;
    }
    
    /**
     *
     */
    public Identity(User user) {
        try {
            this.username = user.getID();

            log.info("Set groupnames via user object for user '" + user.getID() + "' such that also parent groups of groups are loaded!");
            boolean getAlsoParentsOfGroups = true; // NOTE: And their parents, etc.

/*
            String[] groupIDs = user.getGroupIDs(getAlsoParentsOfGroups);
            if (groupIDs != null) {
                groupnames = new String[groupIDs.length];
                for (int i = 0; i < groupIDs.length; i++) {
                    groupnames[i] = groupIDs[i];
                }
            } else {
                log.warn("User/Identity '" + this.username + "' is not a member of any group!");
            }
*/

            // INFO: We only need the group IDs and not the group objects, hence replace this code by the code above as soon as getGroupIDs has been implemented!
            Group[] groups = user.getGroups(getAlsoParentsOfGroups);
            groupnames = new String[groups.length];
            for (int i = 0; i < groups.length; i++) {
                groupnames[i] = groups[i].getID();
            }

        } catch (AccessManagementException e) {
            log.error(e, e);
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Get name of user or null for World
     */
    public String getUsername() {
        return username;
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
    
    public String toString() {
        if (getUsername() == null) return "WORLD";
        return getUsername();
    }

    /**
     * Check whether this identity is world
     */
    public boolean isWorld() {
        return isWorld;
    }
}
