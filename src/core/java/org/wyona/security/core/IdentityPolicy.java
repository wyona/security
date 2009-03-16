package org.wyona.security.core;

import org.wyona.security.core.api.Identity;

/**
 * The XML representation of an IdentityPolicy is <user id="lenya" permission="false"/>
 */
public class IdentityPolicy {

    private Identity identity;
    private boolean permission;

    /**
     *
     */
    public IdentityPolicy(Identity identity, boolean permission) {
        this.identity = identity;
        this.permission = permission;
    }

    /**
     *
     */
    public Identity getIdentity() {
        return identity;
    }

    /**
     *
     */
    public boolean getPermission() {
        return permission;
    }
    
    /**
     * Sets the permission for this policy.
     * The modification is not persistent, it only modifies the policy object in the memory.  
     * @param permission
     */
    public void setPermission(boolean permission) {
        this.permission = permission;
    }
}
