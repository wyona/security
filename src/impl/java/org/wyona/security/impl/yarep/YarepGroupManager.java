package org.wyona.security.impl.yarep;

import java.util.HashMap;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.DefaultConfigurationBuilder;

import org.apache.log4j.Logger;

import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Group;
import org.wyona.security.core.api.GroupManager;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.security.core.api.UserManager;

import org.wyona.yarep.core.NoSuchNodeException;
import org.wyona.yarep.core.Node;
import org.wyona.yarep.core.NodeType;
import org.wyona.yarep.core.Repository;
import org.wyona.yarep.core.RepositoryException;

/**
 * The YarepGroupManager expects to find all existing groups under the node /groups.
 * If the node /groups does not exist, it will look under the root node.
 * All files which have &lt;group&gt; as root element will be recognized as a group
 * configuration. 
 */
public class YarepGroupManager implements GroupManager {
    private static Logger log = Logger.getLogger(YarepGroupManager.class);
    
    protected static final String GROUPS_PARENT_PATH = "/groups";
    private String SUFFIX = "xml";
    
    private Repository identitiesRepository;
    protected UserManager userManager;

    //private boolean cacheEnabled = true;
    private boolean cacheEnabled = false;
    private HashMap cachedGroups;
    //protected HashMap groups;

    /**
     * Constructor.
     * @param identityManager
     * @param identitiesRepository
     * @throws AccessManagementException
     */
    public YarepGroupManager(IdentityManager identityManager, Repository identitiesRepository, boolean cacheEnabled) throws AccessManagementException {
        this.userManager = identityManager.getUserManager();
        this.identitiesRepository = identitiesRepository;
        this.cacheEnabled = cacheEnabled;
    }

    /**
     * Finds all group nodes in the repository and instantiates the groups. 
     * @throws AccessManagementException
     */
    private Group[] loadGroupsFromRepository() throws AccessManagementException {
        log.warn("DEBUG: Load groups from repository '" + identitiesRepository.getName() + "'");
        try {
            DefaultConfigurationBuilder configBuilder = new DefaultConfigurationBuilder(true);
            Node[] groupNodes = getAllGroupNodes();
            java.util.List<Group> groups = new java.util.ArrayList<Group>();
            for (int i = 0; i < groupNodes.length; i++) {
                if (groupNodes[i].getName().endsWith("." + SUFFIX)) {
                    try {
                        Configuration config = configBuilder.build(groupNodes[i].getInputStream());
                        if (config.getName().equals(YarepGroup.GROUP_TAG_NAME)) {
                            Group group = constructGroup(groupNodes[i]);
                            groups.add(group);
                        } else {
                            log.error("Node '" + groupNodes[i].getPath() + "'  does not seem to be a group!");
                        }
                    } catch (Exception e) {
                        String errorMsg = "Could not create group from repository node: " + groupNodes[i].getPath() + ": " + e;
                        log.error(errorMsg, e);
                        // NOTE[et]: Do not fail here because other groups may still be ok
                        //throw new AccessManagementException(errorMsg, e);
                    }
                } else {
                    log.error("Node '" + groupNodes[i].getPath() + "'  does not seem to be a group, because it has not the suffix '" + "." + SUFFIX + "'!");
                }
            }
            return (Group[])groups.toArray(new Group[groups.size()]);
        } catch (RepositoryException e) {
            String errorMsg = "Could not read groups from repository: " + e;
            log.error(errorMsg, e);
            throw new AccessManagementException(errorMsg, e);
        }
    }

    /**
     * Finds all group nodes within the Yarep repository. 
     * @throws AccessManagementException
     */
    public Node[] getAllGroupNodes() throws AccessManagementException {
        log.debug("Get group nodes from repository '" + identitiesRepository.getName() + "'");
        try {
            Node groupsParentNode = getGroupsParentNode();
            Node[] nodes = groupsParentNode.getNodes();
            java.util.List<Node> groupNodes = new java.util.ArrayList<Node>();
            for (int i = 0; i < nodes.length; i++) {
                if (nodes[i].isResource()) {
                    groupNodes.add(nodes[i]);
                }
            }
            return (Node[])groupNodes.toArray(new Node[groupNodes.size()]);
        } catch (RepositoryException e) {
            log.error(e, e);
            String errorMsg = "Could not read groups from repository: " + e;
            throw new AccessManagementException(errorMsg, e);
        }
    }

    /**
     * @see org.wyona.security.core.api.GroupManager#createGroup(java.lang.String, java.lang.String)
     */
    public Group createGroup(String id, String name) throws AccessManagementException {
        if (existsGroup(id)) {
            throw new AccessManagementException("Group " + id + " already exists.");
        }
        try {
            Node groupsParentNode = getGroupsParentNode();
            YarepGroup group = new YarepGroup(userManager, this, id, name);
            group.setNode(groupsParentNode.addNode(id + "." + SUFFIX, NodeType.RESOURCE));
            group.save();

            if (cacheEnabled) {
                loadGroupIntoCache(id);
            }

            return group;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AccessManagementException(e.getMessage(), e);
        }
    }
    
    /**
     * Override in subclasses
     * @param node Repository node of group
     */
    protected Group constructGroup(Node node) throws AccessManagementException{
        return new YarepGroup(userManager, this, node);
    }

    /**
     * @see org.wyona.security.core.api.GroupManager#existsGroup(java.lang.String)
     */
    public boolean existsGroup(String id) throws AccessManagementException {
        // Check the cache first
        if (!existsWithinCache(id)) {
            // Also check the repository
            return existsWithinRepository(id);
        }
        return true;
    }

    /**
     * Check if group exists within cache
     */
    private boolean existsWithinCache(String userId) {
        if (cacheEnabled && cachedGroups!= null && cachedGroups.containsKey(userId)) return true;
        return false;
    }

    /**
     * Check whether group exists within persistent identities repository
     */
    private boolean existsWithinRepository(String id) throws AccessManagementException {
        try {
            return getGroupsParentNode().hasNode(id + "." + SUFFIX);
        } catch(Exception e) {
            log.error(e, e);
            return false;
        }
    }

    /**
     * @see org.wyona.security.core.api.GroupManager#getGroup(java.lang.String)
     */
    public Group getGroup(String id) throws AccessManagementException {
        if (!existsGroup(id)) {
            log.warn("No such group: " + id);
            return null;
        } else {
            if (cacheEnabled) {
                if (!existsWithinCache(id)) {
                    loadGroupIntoCache(id);
                }
                log.warn("Get group '" + id + "' from cache.");
                return (Group) cachedGroups.get(id);
            } else {
                log.debug("Get group '" + id + "' from repository.");
                return getGroupFromPersistentRepository(id);
            }
        }
    }

    /**
     * Get group from repository
     */
    private Group getGroupFromPersistentRepository(String id) throws AccessManagementException {
        if (existsWithinRepository(id)) {
            try {
                return constructGroup(getGroupsParentNode().getNode(id + "." + SUFFIX));
            } catch (Exception e) {
                log.error(e, e);
                throw new AccessManagementException(e.getMessage());
            }
        }
        log.warn("No such group within persistent repository: " + id);
        return null;
    }

    /**
     * @see org.wyona.security.core.api.GroupManager#getGroups()
     */
    public Group[] getGroups() throws AccessManagementException {
        log.warn("This method does not scale well. Rather use an iterator!");
        if (cacheEnabled && cachedGroups != null) {
            return (Group[]) cachedGroups.values().toArray(new Group[cachedGroups.size()]);
        } else {
            return loadGroupsFromRepository();
        }
    }

    /**
     * @see org.wyona.security.core.api.GroupManager#removeGroup(java.lang.String)
     */
    public void removeGroup(String id) throws AccessManagementException {
        if (!existsGroup(id)) {
            throw new AccessManagementException("Group " + id + " does not exist.");
        }
        Group group = getGroup(id);
   
        if (cacheEnabled && existsWithinCache(id)) {
            cachedGroups.remove(id);
        }
        group.delete();
    }

    /**
     * Gets the repository node which is the parent node of all group nodes.
     * @return parent node of group nodes
     * @throws NoSuchNodeException
     * @throws RepositoryException
     */
    protected Node getGroupsParentNode() throws NoSuchNodeException, RepositoryException {
        if (this.identitiesRepository.existsNode(GROUPS_PARENT_PATH)) {
            return this.identitiesRepository.getNode(GROUPS_PARENT_PATH);
        }
        // fallback to root node for backwards compatibility:
        return this.identitiesRepository.getNode("/");    
    }

    /**
     * Loads a specific group from persistance storage into memory
     *
     * @param id Group id
     * @throws AccessManagementException
     */
    protected synchronized void loadGroupIntoCache(String id) throws AccessManagementException {
        log.warn("DEBUG: Load group '" + id + "' from persistent repository '" + identitiesRepository.getName() + "' into cache.");
        if (cachedGroups == null) {
            log.warn("No groups yet within memory. Initialize groups hash map.");
            cachedGroups = new HashMap();
        }
        if (cachedGroups.containsKey(id)) {
            log.warn("Group '" + id + "' already exists within memory, but will be reloaded!");
        } else {
            log.warn("Group '" + id + "' does not exist wihtin memory yet, but will be loaded now!");
        }

        Group group = getGroupFromPersistentRepository(id);
        if (group != null) {
            cachedGroups.put(id, group);
        }
    }

    /**
     * Check whether cache is enabled
     */
    protected boolean isCacheEnabled() {
        return cacheEnabled;
    }
}
