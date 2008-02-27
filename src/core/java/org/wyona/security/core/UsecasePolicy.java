package org.wyona.security.core;

import org.wyona.security.core.api.Identity;
import org.wyona.security.core.api.Group;

import java.util.Vector;

/**
 *
 */
public class UsecasePolicy {

    private String name;

    private Vector identities = null;
    private Vector groups = null;

    /**
     *
     */
    public UsecasePolicy(String name) {
        this.name = name;
        identities = new Vector();
    }

    /**
     *
     */
    public String getName() {
        return name;
    }

    /**
     *
     */
    public void addIdentity(Identity identity) {
        identities.add(identity);
    }

    /**
     *
     */
    public Identity[] getIdentities() {
        Identity[] ids = new Identity[identities.size()];
        for (int i = 0; i < ids.length; i++) {
            ids[i] = (Identity) identities.elementAt(i);
        }
        return ids;
    }

    /**
     *
     */
    public void addGroup(Group group) {
        groups.add(group);
    }

    /**
     *
     */
    public Group[] getGroups() {
        Group[] gs = new Group[groups.size()];
        for (int i = 0; i < gs.length; i++) {
            gs[i] = (Group) groups.elementAt(i);
        }
        return gs;
    }
}
