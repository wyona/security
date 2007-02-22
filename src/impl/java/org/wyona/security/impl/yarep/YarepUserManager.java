package org.wyona.security.impl.yarep;

import java.util.HashMap;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.DefaultConfigurationBuilder;
import org.apache.log4j.Category;
import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Group;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.security.core.api.User;
import org.wyona.security.core.api.UserManager;
import org.wyona.yarep.core.NoSuchNodeException;
import org.wyona.yarep.core.Node;
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

    private static Category log = Category.getInstance(YarepUserManager.class);
    
    private Repository identitiesRepository;

    private IdentityManager identityManager;

    private HashMap users;

    /**
     * Constructor.
     * @param identityManager
     * @param identitiesRepository
     * @throws AccessManagementException
     */
    public YarepUserManager(IdentityManager identityManager, Repository identitiesRepository)
            throws AccessManagementException {
        this.identityManager = identityManager;
        this.identitiesRepository = identitiesRepository;
        this.users = new HashMap();
        init();
    }

    /**
     * Finds all user nodes in the repository and instantiates the users. 
     * @throws AccessManagementException
     */
    protected void init() throws AccessManagementException {
        try {
            Node usersParentNode = getUsersParentNode();
            Node[] userNodes = usersParentNode.getNodes();
            DefaultConfigurationBuilder configBuilder = new DefaultConfigurationBuilder(true);
            for (int i = 0; i < userNodes.length; i++) {
                if (userNodes[i].isResource()) {
                    Configuration config = configBuilder.build(userNodes[i].getInputStream());
                    // also support identity for backwards compatibility
                    if (config.getName().equals(YarepUser.USER) || config.getName().equals("identity")) {
                        YarepUser user = new YarepUser(this.identityManager, userNodes[i]);
                        this.users.put(user.getID(), user);
                    }
                }
            }
        } catch (NoSuchNodeException e) {
            log.error("Node /users not found in repository" + e.getMessage(), e);
            // ignore error
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AccessManagementException(e.getMessage(), e);
        }
    }

    /**
     * @see org.wyona.security.core.api.UserManager#createUser(java.lang.String, java.lang.String, java.lang.String, java.lang.String)
     */
    public User createUser(String id, String name, String email, String password)
            throws AccessManagementException {
        if (existsUser(id)) {
            throw new AccessManagementException("User " + id + " already exists.");
        }
        try {
            Node usersParentNode = getUsersParentNode();
            User user = new YarepUser(this.identityManager, usersParentNode, id, name, email,
                    password);
            user.save();
            this.users.put(id, user);
            return user;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AccessManagementException(e.getMessage(), e);
        }
    }

    /**
     * @see org.wyona.security.core.api.UserManager#existsUser(java.lang.String)
     */
    public boolean existsUser(String id) throws AccessManagementException {
        return this.users.containsKey(id);
    }

    /**
     * @see org.wyona.security.core.api.UserManager#getUser(java.lang.String)
     */
    public User getUser(String id) throws AccessManagementException {
        if (!existsUser(id)) {
            return null;
        }
        return (User) this.users.get(id);
    }

    /**
     * @see org.wyona.security.core.api.UserManager#getUsers()
     */
    public User[] getUsers() throws AccessManagementException {
        return (User[]) this.users.values().toArray(new User[this.users.size()]);
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
        for (int i=0; i<groups.length; i++) {
            groups[i].removeMember(user);
            groups[i].save();
        }
        this.users.remove(id);
        user.delete();
    }

    /**
     * Gets the repository node which is the parent node of all user nodes.
     * @return parent node of users node.
     * @throws NoSuchNodeException
     * @throws RepositoryException
     */
    protected Node getUsersParentNode() throws NoSuchNodeException, RepositoryException {
        if (this.identitiesRepository.existsNode("/users")) {
            return this.identitiesRepository.getNode("/users");
        }
        // fallback to root node for backwards compatibility:
        return this.identitiesRepository.getNode("/");
    }

}