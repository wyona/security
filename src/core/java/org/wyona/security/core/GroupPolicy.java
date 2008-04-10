package org.wyona.security.core;

/**
 *
 */
public class GroupPolicy {

    private String groupId;
    private boolean permission;

    /**
     *
     */
    public GroupPolicy(String groupId, boolean permission) {
        this.groupId = groupId;
        this.permission = permission;
    }

    /**
     *
     */
    public String getId() {
        return groupId;
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
