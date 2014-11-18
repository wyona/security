package org.wyona.security.core.api;

/**
 * Manages users.
 */
public interface UserManager {

    /**
     * Gets all users in no particular order. Please note that this method does not scale well for a system with many users (e.g. greater than 500), but for a smaller user base this method is very convenient
     *  
     * @return array of users, empty array if no users exist.
     * @throws AccessManagementException
     */
    User[] getUsers() throws AccessManagementException;

    /**
     * Gets all users. Please note that this method does not make sense for systems with gigantic amount of users (e.g. > 1 Mio), but for a system with thousands of users it should be fine
     *
     * @return Users in no particular order.
     * @throws AccessManagementException
     */
    java.util.Iterator<User> getAllUsers() throws AccessManagementException;

    /**
     * Gets users matching a simple search query (assuming this is implemented as a fulltext search). Please note that this method is intended for systems with gigantic amount of users (e.g. > 500 Mio).
     *
     * @param query Simple search query
     * @return Users in no particular order.
     * @throws AccessManagementException
     */
    java.util.Iterator<User> getUsers(String query) throws AccessManagementException;

    /**
     * Get total number of users.
     */
    int getUserCount();

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
     * @param refresh TODO
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
     * Creates an alias for an existing user or alias
     * @param alias Alias name
     * @param username Name of existing user
     * @return user referenced by alias
     */
    User createAlias(String alias, String username) throws AccessManagementException;

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
     * Delete alias (but not actual user, whereas depending on implementation the removal of the last alias might also delete the actual user!)
     * @param alias Alias name of user
     */
    void removeAlias(String alias) throws AccessManagementException;

    /**
     * Indicates whether a user with the given id exists.
     * 
     * @param id True ID of user
     * @return true if a user with the given id exists.
     * @throws AccessManagementException
     */
    boolean existsUser(String id) throws AccessManagementException;

    /**
     * Indicates whether an alias with the given id exists.
     * 
     * @param id ID of alias
     * @return true if an alias with the given id exists.
     * @throws AccessManagementException
     */
    boolean existsAlias(String id) throws AccessManagementException;

    /**
     * Get the true ID of a user
     * 
     * @param id Either pseudonym or true ID
     * @return true ID if a user with the given id exists as pseudonym or as a true ID.
     * @throws AccessManagementException
     */
    String getTrueId(String id) throws AccessManagementException;
}
