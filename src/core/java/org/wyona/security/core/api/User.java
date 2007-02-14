package org.wyona.security.core.api;

/**
 * A user.
 */
public interface User extends Item {
    /**
     * Gets the email address of this user.
     * 
     * @return email address
     * @throws AccessManagementException
     */
    String getEmail() throws AccessManagementException;

    /**
     * Sets the email address of this user. The user is not saved automatically.
     * 
     * @param email
     * @throws AccessManagementException
     */
    void setEmail(String email) throws AccessManagementException;

    /**
     * Sets the password. The parameter may be passed in cleartext, the
     * implementation is reponsible for encrypting the password.
     * 
     * @param password
     *            as cleartext
     * @throws AccessManagementException
     */
    void setPassword(String password) throws AccessManagementException;

    /**
     * Authenticates this user by verifying the password.
     * 
     * @param password
     *            as cleartext
     * @return
     * @throws AccessManagementException
     */
    boolean authenticate(String password) throws AccessManagementException;

    /**
     * Gets all groups this user is a member of.
     * 
     * @return array of groups, empty array if this user is not a member of any group.
     * @throws AccessManagementException
     */
    Group[] getGroups() throws AccessManagementException;
}