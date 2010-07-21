package org.wyona.security.core.api;

/**
 * Manages users.
 */
public interface UserManager {

    /**
     * Gets all users in no particular order.
     * 
     * XXX: this does not scale UI-wise for many users:
     *  we should probably add a method like
     *  <code>Iterator&lt;User&gt; findUsers(String pattern)</code>,
     *  <var>pattern</var> being an implementation-specific search string.
     *  We may also need server-side sort and paging.
     *  
     * @return array of users, empty array if no users exist.
     * @throws AccessManagementException
     */
    User[] getUsers() throws AccessManagementException;

    /**
     * Gets all users in no particular order, whereas provides a parameter to tell the implementation to refresh possibly cached entries
     * 
     * XXX: this does not scale UI-wise for many users: cf. {@link UserManager#getUsers()} for rationale.
     *  
     * @return array of users, empty array if no users exist.
     * @throws AccessManagementException
     */
    User[] getUsers(boolean refresh) throws AccessManagementException;

    /**
     * Gets the user with the given id.
     * 
     * @param id True ID of user
     * @return user or null if no user with the given id exists 
     * @throws AccessManagementException
     */
    User getUser(String id) throws AccessManagementException;

    /**
     * Gets the user with the given id, whereas provides a parameter to tell the implementation to refresh a possible cached entry
     * 
     * @param id True ID of user
     * @param refresh
     * @return user or null if no user with the given id exists 
     * @throws AccessManagementException
     */
    User getUser(String id, boolean refresh) throws AccessManagementException;

    /**
     * Creates a new user. The new user will be saved automatically.
     * 
     * @param id True ID of user
     * @param name Name (e.g. first and last) of user
     * @param email Primary email address
     * @param password Password in cleartext
     * @return new user
     * @throws AccessManagementException
     *             if a user with the given id already exists or if something
     *             else goes wrong.
     */
    User createUser(String id, String name, String email, String password)
            throws AccessManagementException;

    /**
     * Permanently deletes the user and deletes all group memberships of the
     * user.
     * 
     * @param id True ID of user
     * @throws AccessManagementException
     *             if no user with the given id exists or if something else goes
     *             wrong.
     */
    void removeUser(String id) throws AccessManagementException;

    /**
     * Indicates whether a user with the given id exists.
     * 
     * @param id True ID of user
     * @return true if a user with the given id exists.
     * @throws AccessManagementException
     */
    boolean existsUser(String id) throws AccessManagementException;

    /**
     * Get the true ID of a user
     * 
     * @param id Either pseudonym or true ID
     * @return true ID if a user with the given id exists as pseudonym or as a true ID.
     * @throws AccessManagementException
     */
    String getTrueId(String id) throws AccessManagementException;
}
