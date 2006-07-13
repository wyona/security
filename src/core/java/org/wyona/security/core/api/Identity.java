package org.wyona.security.core.api;

/**
 *
 */
public class Identity implements java.io.Serializable {

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
