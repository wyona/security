package org.wyona.security.core;

/**
 * Holds the permission for a policy for a given {@linkplain org.wyona.security.core.api.Item security item}.
 */
public abstract class ItemPolicy {

    private boolean permission;

    protected ItemPolicy(boolean permission) {
        this.permission = permission;
    }

    /**
     * Gets the permission for this policy and this security item.
     */
    public boolean getPermission() {
        return permission;
    }
    
    /**
     * Sets the permission for this policy and this security item.
     * The modification is not persistent, it only modifies the policy object in the memory.  
     * @param permission the permission to set
     */
    public void setPermission(boolean permission) {
        this.permission = permission;
    }

    /**
     * Gets the ID of the security item (may be <samp>null</samp>).
     */
    public abstract String getId();
}
