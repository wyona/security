package org.wyona.security.core.api;

import org.apache.log4j.Category;

/**
 *
 */
public class Identity implements java.io.Serializable {

    private static Category log = Category.getInstance(Identity.class);
    
    protected String username;
    protected String[] groupnames;

    protected User user;
    
    /**
     * Identity is WORLD
     */
    public Identity() {
        username = null;
        groupnames = null;
    }

    /**
     * @deprecated
     */
    public Identity(String username, String[] groupnames) {
        this.username = username;
        this.groupnames = groupnames;
    }
    
    public Identity(User user) {
        this.user = user;
    }

    /**
     * @deprecated
     * use getUser() instead
     */
    public String getUsername() {
        if (username != null) {
            return username;
        } else {
            try {
                if (this.user == null) {
                    return null;
                } else {
                    return this.user.getID();
                }
            } catch (AccessManagementException e) {
                log.error(e.getMessage(), e);
                throw new RuntimeException(e.getMessage(), e); //FIXME
            }
        }
    }
    
    public User getUser() {
        return this.user;
    }

    /**
     * @deprecated
     * use getGroups() instead
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
            return null;
        }
    }
    
    public Group[] getGroups() throws AccessManagementException {
        return this.user.getGroups();
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
}
