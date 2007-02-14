package org.wyona.security.core.api;

/**
 * Group of items, whereas an item is normally a user of a host.
 */
public interface Group extends Item {
    /**
     * Gets all members of this group in no particular order.
     * 
     * @return array of members, or empty array if there are no members.
     * @throws AccessManagementException
     */
    Item[] getMembers() throws AccessManagementException;

    /**
     * Adds a member to this group.
     * The group is not saved automatically.
     * 
     * @param item
     * @throws AccessManagementException
     *             if item already is a member of this group, or if something
     *             else goes wrong.
     */
    void addMember(Item item) throws AccessManagementException;

    /**
     * Removes item from this group.
     * The group is not saved automatically.
     * 
     * @param item
     * @throws AccessManagementException
     *             if item is not a member of this group, or if something else
     *             goes wrong.
     */
    void removeMember(Item item) throws AccessManagementException;

    /**
     * Indicates whether the item is a member of this group.
     * 
     * @param item
     * @return true if the item is a member of this group, false otherwise.
     * @throws AccessManagementException
     */
    boolean isMember(Item item) throws AccessManagementException;
}