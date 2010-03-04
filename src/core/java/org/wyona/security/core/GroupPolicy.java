package org.wyona.security.core;

/**
 * {@inheritDoc}
 * 
 * The XML representation of a GroupPolicy is e.g. {@code <group id="staff" permission="false"/>}.
 */
public class GroupPolicy extends ItemPolicy {

    private String groupId;

    /**
     *
     */
    public GroupPolicy(String groupId, boolean permission) {
        super(permission);
        this.groupId = groupId;
    }

    /**
     * Gets the ID of the group (never <samp>null</samp>).
     */
    @Override
    public String getId() {
        return groupId;
    }
}
