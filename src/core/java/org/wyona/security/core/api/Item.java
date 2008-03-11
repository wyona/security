package org.wyona.security.core.api;

/**
 * An Item is a generalization of users, hosts, etc.
 */
public interface Item {

    /**
     * Gets the id of this item.
     * The id is immutable.
     * @return id
     * @throws AccessManagementException
     */
    String getID() throws AccessManagementException;

    /** 
     * Gets the name of this item
     * @return name
     * @throws AccessManagementException
     */
    String getName() throws AccessManagementException;

    /**
     * Sets the name of this item.
     * The item is not saved automatically.
     * @param name
     * @throws AccessManagementException
     */
    void setName(String name) throws AccessManagementException;

    /**
     * Permanentely deletes this item.
     * @throws AccessManagementException
     */
    void delete() throws AccessManagementException;

    /**
     * Saves any changes of this item.
     * @throws AccessManagementException
     */
    void save() throws AccessManagementException;
}
