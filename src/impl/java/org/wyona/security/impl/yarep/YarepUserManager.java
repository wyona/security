package org.wyona.security.impl.yarep;

import java.util.HashMap;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.DefaultConfigurationBuilder;
import org.apache.log4j.Logger;
import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Group;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.security.core.api.User;
import org.wyona.security.core.api.UserManager;
import org.wyona.yarep.core.NoSuchNodeException;
import org.wyona.yarep.core.Node;
import org.wyona.yarep.core.NodeType;
import org.wyona.yarep.core.Repository;
import org.wyona.yarep.core.RepositoryException;

/**
 * The YarepUserManager expects to find all existing users under the node /users.
 * If the node /users does not exist, it will look under the root node.
 * All files which have &lt;user&gt; as root element will be recognized as a user
 * configuration. &lt;identity&gt; is also recognized as a user for backwards 
 * compatibility.
 */
public class YarepUserManager implements UserManager {
    protected static Logger log = Logger.getLogger(YarepUserManager.class);
    
    private Repository identitiesRepository;

    protected IdentityManager identityManager;

    private boolean cacheEnabled = false;
    private HashMap cachedUsers;

    private boolean resolveGroupsAtCreation = false;

    private String SUFFIX = "xml";
    private String DEPRECATED_SUFFIX = "iml";

    /**
     * Constructor.
     *
     * @param identityManager
     * @param identitiesRepository
     * @param cacheEnabled Flag to enable memory cache
     * @param resolveGroupsAtCreation Flag to resolve groups if user is created and maybe existed before
     *
     * @throws AccessManagementException
     */
    public YarepUserManager(IdentityManager identityManager, Repository identitiesRepository, boolean cacheEnabled, boolean resolveGroupsAtCreation) throws AccessManagementException {
    //public YarepUserManager(IdentityManager identityManager, Repository identitiesRepository) throws AccessManagementException {
        this.identityManager = identityManager;
        this.identitiesRepository = identitiesRepository;
        this.cacheEnabled = cacheEnabled;
        this.resolveGroupsAtCreation = resolveGroupsAtCreation;
    }

    /**
     * Finds all user nodes in the repository and instantiates the users.
     *
     * Note re caching: If the UserManager is being instantiated only once at the startup of a server for instance, then the users are basically being cached (see getUser) and changes within the repository by a third pary application will not be noticed.
     *
     * @throws AccessManagementException
     */
    private User[] loadUsersFromRepository() throws AccessManagementException {
        log.info("Load users from repository '" + identitiesRepository.getConfigFile() + "'");
        try {
            Node usersParentNode = getUsersParentNode();
            // TODO: There seems to be a bug such that users like ac-identities/http\:/michaelwechner.livejournal.com/.xml are not being detected either by getNodes() or isResource()!
            Node[] userNodes = usersParentNode.getNodes();
            DefaultConfigurationBuilder configBuilder = new DefaultConfigurationBuilder(true);

            java.util.List<User> users = new java.util.ArrayList<User>();
            for (int i = 0; i < userNodes.length; i++) {
                if (userNodes[i].isResource()) {
                    try {
                        Configuration config = configBuilder.build(userNodes[i].getInputStream());
                        // also support identity for backwards compatibility
                        if (config.getName().equals(YarepUser.USER) || config.getName().equals("identity")) {
                            User user = constructUser(this.identityManager, userNodes[i]);
                            log.debug("User (re)loaded: " + userNodes[i].getName() + ", " + user.getID());
                            users.add(user);
                        }
                    } catch (Exception e) {
                        String errorMsg = "Could not create user from repository node: " + userNodes[i].getPath() + ": " + e.getMessage();
                        log.error(errorMsg, e);
                        // NOTE[et]: Do not fail here because other users may still be ok
                        //throw new AccessManagementException(errorMsg, e);
                    }
                }
            }
            return (User[])users.toArray(new User[users.size()]);
        } catch (RepositoryException e) {
            String errorMsg = "Could not read users from repository: " + e.getMessage();
            log.error(errorMsg, e);
            throw new AccessManagementException(errorMsg, e);
        }
    }

    /**
     * Loads a specific user from persistance storage into memory
     *
     * @param id User id
     * @throws AccessManagementException
     */
    protected synchronized void loadUserIntoCache(String id) throws AccessManagementException {
        log.warn("DEBUG: Load user '" + id + "' from persistent repository '" + identitiesRepository.getName() + "' into cache.");
        if (cachedUsers == null) {
            log.warn("No users yet within memory. Initialize users hash map.");
            cachedUsers = new HashMap();
        }
        if (cachedUsers.containsKey(id)) {
            log.warn("User '" + id + "' already exists within memory, but will be reloaded!");
        } else {
            log.warn("User '" + id + "' does not exist wihtin memory yet, but will be loaded now!");
        }

        User user = getUserFromPersistentRepository(id);
        if (user != null) {
            cachedUsers.put(id, user);
        }
    }

    /**
     * @see org.wyona.security.core.api.UserManager#createUser(java.lang.String, java.lang.String, java.lang.String, java.lang.String)
     */
    public User createUser(String id, String name, String email, String password) throws AccessManagementException {
        if (existsUser(id)) {
            throw new AccessManagementException("User " + id + " already exists!");
        }
        try {
            Node usersParentNode = getUsersParentNode();
            YarepUser user = new YarepUser(this, identityManager.getGroupManager(), id, name);
            if (email != null) {
                user.setEmail(email);
            }
            if (password != null) {
                user.setPassword(password);
            }

            user.setNode(usersParentNode.addNode(id + "." + SUFFIX, NodeType.RESOURCE));

            if (resolveGroupsAtCreation) {
                String[] groupIDs = user.getGroupIDs(false);
                if (groupIDs != null) {
                    for (int i = 0; i < groupIDs.length; i++) {
                        log.warn("DEBUG: New user '" + id + "'  belongs to group '" + groupIDs[i] + "' (This user probably existed before and groups were not cleaned at the time this user was deleted!)");
                        user.addGroup(groupIDs[i]);
                    }
                }
            }

            user.save();

            // INFO: Add to cache
            if (cacheEnabled) {
                loadUserIntoCache(id);
            }

            return user;
        } catch (Exception e) {
            log.error(e, e);
            throw new AccessManagementException(e.getMessage(), e);
        }
    }

    /**
     * Check if user exists within cache
     */
    private boolean existsWithinCache(String userId) {
        if (cacheEnabled && cachedUsers!= null && cachedUsers.containsKey(userId)) return true;
        return false;
    }

    /**
     * Check if user exists within persistent identities repository
     */
    private boolean existsWithinRepository(String userId) {
        try {
            Node usersParentNode = getUsersParentNode();

            // Check .iml suffix in order to stay backwards compatible
            if (usersParentNode.hasNode(userId + "." + DEPRECATED_SUFFIX)) {
                log.warn("Deprecated user node path '" + userId + "." + DEPRECATED_SUFFIX + "' within repository '" + identitiesRepository.getName() + "'. Please upgrade by replacing the suffix '." + DEPRECATED_SUFFIX + "' by '." + SUFFIX + "'");
                return true;
            }

            if (usersParentNode.hasNode(userId + "." + SUFFIX)) return true;
        } catch (Exception e) {
            log.warn(e.getMessage(), e);
        }
        log.warn("No such user within persistent repository: " + userId);
        return false;
    }

    /**
     * @see org.wyona.security.core.api.UserManager#existsUser(java.lang.String)
     */
    public boolean existsUser(String id) throws AccessManagementException {
        // Check the cache first
        if (!existsWithinCache(id)) {
            // Also check the repository
            return existsWithinRepository(id);
        }
        return true;
    }

    /**
     * Get user from repository
     */
    private User getUserFromPersistentRepository(String id) throws AccessManagementException {
        //log.debug("Get user '" + id + "' from persistent repository.");
        if (existsWithinRepository(id)) {
            try {

                String trueId;
                Node aliasesParentNode = getAliasesParentNode();
                if (aliasesParentNode != null) {
                    log.warn("TODO: Get true ID from alias...");
                    trueId = id;
                } else {
                    trueId = id;
                }

                String nodeName = trueId + "." + SUFFIX;
                Node usersParentNode = getUsersParentNode();

                // Check for .iml suffix in order to stay backwards compatible
                if (!usersParentNode.hasNode(nodeName)) {
                    nodeName = trueId + "." + DEPRECATED_SUFFIX;
                }

                return constructUser(this.identityManager, usersParentNode.getNode(nodeName));
            } catch (Exception e) {
                log.error(e, e);
                throw new AccessManagementException(e.getMessage());
            }
        }
        log.warn("No such user within persistent repository: " + id);
        return null;
    }

    /**
     * @see org.wyona.security.core.api.UserManager#getUser(java.lang.String)
     */
    public User getUser(String id) throws AccessManagementException {
        if (cacheEnabled && existsWithinCache(id)) {
            log.warn("Get user '" + id + "' from cache.");
            return (User) cachedUsers.get(id);
        } else {
            return getUser(id, true);
        }
    }

    /**
     * @see org.wyona.security.core.api.UserManager#getUser(java.lang.String, boolean)
     */
    public User getUser(String id, boolean refresh) throws AccessManagementException {
        if (refresh) {
/*
            log.warn("Refresh of group manager after reloading all users, such that user '" + id + "' has access to a refreshed group manager!");
            ((YarepGroupManager)identityManager.getGroupManager()).loadGroups();
*/
            if (cacheEnabled) {
                log.warn("Update user '" + id + "' within cache.");
                loadUserIntoCache(id);
                return (User) cachedUsers.get(id);
            } else {
                return getUserFromPersistentRepository(id);
            }
        } else {
            if (cacheEnabled) {
                if (!existsWithinCache(id)) {
                    log.warn("User cache does not exist yet, hence user '" + id + "' will be loaded into cache ...");
                    loadUserIntoCache(id);
                }
                return (User) cachedUsers.get(id);
            } else {
                log.warn("Cache is disabled, hence get user '" + id + "' from repository");
                return getUserFromPersistentRepository(id);
            }
        }
    }

    /**
     * @see org.wyona.security.core.api.UserManager#getUsers()
     */
    public User[] getUsers() throws AccessManagementException {
        log.warn("This method does not scale well. Rather use an iterator!");
        if (cacheEnabled && cachedUsers != null) {
            return (User[]) cachedUsers.values().toArray(new User[cachedUsers.size()]);
        } else {
            return getUsers(true);
        }
    }

    /**
     * @see org.wyona.security.core.api.UserManager#getUsers(boolean)
     */
    public User[] getUsers(boolean refresh) throws AccessManagementException {
        if (refresh) {
            return loadUsersFromRepository();
        } else {
            if (cacheEnabled) {
                if (cachedUsers == null) {
                    log.warn("User cache does not exist yet, hence users will be loaded into cache ...");
                    cachedUsers = new HashMap();
                    User[] users = loadUsersFromRepository();
                    for (int i = 0; i < users.length; i++) {
                        cachedUsers.put(users[i].getID(), users[i]);
                    }
                }
                return (User[]) cachedUsers.values().toArray(new User[cachedUsers.size()]);
            } else {
                log.warn("Cache is disabled, hence get users from repository");
                return loadUsersFromRepository();
            }
        }


/*
        if(refresh){
            loadUsers();
            log.info("Refresh of group manager after reloading all users, such that users have access to a refreshed group manager!");
            ((YarepGroupManager)identityManager.getGroupManager()).loadGroups();
        }
        return getUsers();
*/
    }

    /**
     * @see org.wyona.security.core.api.UserManager#removeUser(java.lang.String)
     */
    public void removeUser(String id) throws AccessManagementException {
        if (!existsUser(id)) {
            throw new AccessManagementException("User " + id + " does not exist.");
        }
        User user = getUser(id);

        Group[] groups = user.getGroups();
        for (int i = 0; i < groups.length; i++) {
            groups[i].removeMember(user);
            groups[i].save();
        }

        if (cacheEnabled && existsWithinCache(id)) {
            cachedUsers.remove(id);
        }

        user.delete();
    }

    /**
     * Gets the repository node which is the parent node of all user nodes.
     *
     * @return node which is the parent of all user nodes.
     * @throws NoSuchNodeException
     * @throws RepositoryException
     */
    protected Node getUsersParentNode() throws NoSuchNodeException, RepositoryException {
        if (this.identitiesRepository.existsNode("/users")) {
            return this.identitiesRepository.getNode("/users");
        }

        log.warn("Fallback to root node (Repository: " + identitiesRepository.getName() + ") for backwards compatibility. Please upgrade by introducing a /users node!");
        return this.identitiesRepository.getNode("/");
    }

    /**
     * Gets the repository node which is the parent node of all aliases nodes.
     *
     * @return node which is the parent of all aliases nodes.
     * @throws NoSuchNodeException
     * @throws RepositoryException
     */
    protected Node getAliasesParentNode() throws NoSuchNodeException, RepositoryException {
        if (this.identitiesRepository.existsNode("/aliases")) {
            return this.identitiesRepository.getNode("/aliases");
        }
        log.warn("No 'aliases' set yet!");
        return null;
    }
    
    /**
     * Override in subclasses
     * @param node Repository node of user
     */
    protected User constructUser(IdentityManager identityManager, Node node) throws AccessManagementException{
        return new YarepUser(this, identityManager.getGroupManager(), node);
    }

    /**
     *
     */
    protected boolean isCacheEnabled() {
        return cacheEnabled;
    }
}
