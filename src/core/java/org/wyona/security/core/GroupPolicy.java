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
    public GroupPolicy(String groupId) {
        this.groupId = groupId;
        this.permission = true;
    }

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
}
