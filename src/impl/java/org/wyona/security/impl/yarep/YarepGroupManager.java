package org.wyona.security.impl.yarep;

import java.util.HashMap;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.DefaultConfigurationBuilder;
import org.apache.log4j.Category;
import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Group;
import org.wyona.security.core.api.GroupManager;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.yarep.core.NoSuchNodeException;
import org.wyona.yarep.core.Node;
import org.wyona.yarep.core.Repository;
import org.wyona.yarep.core.RepositoryException;

public class YarepGroupManager implements GroupManager {

    private static Category log = Category.getInstance(YarepGroupManager.class);
    
    private Repository identitiesRepository;

    private IdentityManager identityManager;

    private HashMap groups;

    public YarepGroupManager(IdentityManager identityManager, Repository identitiesRepository)
            throws AccessManagementException {
        this.identityManager = identityManager;
        this.identitiesRepository = identitiesRepository;
        this.groups = new HashMap();
        init();
    }

    protected void init() throws AccessManagementException {
        try {
            Node groupsParentNode = getGroupsParentNode();
            Node[] groupNodes = groupsParentNode.getNodes();
            DefaultConfigurationBuilder configBuilder = new DefaultConfigurationBuilder(true);
            for (int i = 0; i < groupNodes.length; i++) {
                if (groupNodes[i].isResource()) {
                    Configuration config = configBuilder.build(groupNodes[i].getInputStream());
                    if (config.getName().equals(YarepGroup.GROUP)) {
                        YarepGroup group = new YarepGroup(this.identityManager, groupNodes[i]);
                        this.groups.put(group.getID(), group);
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
     * @see org.wyona.security.core.api.GroupManager#createGroup(java.lang.String, java.lang.String)
     */
    public Group createGroup(String id, String name) throws AccessManagementException {
        if (existsGroup(id)) {
            throw new AccessManagementException("Group " + id + " already exists.");
        }
        try {
            Node groupsParentNode = getGroupsParentNode();
            Group group = new YarepGroup(this.identityManager, groupsParentNode, id, name);
            group.save();
            this.groups.put(id, group);
            return group;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AccessManagementException(e.getMessage(), e);
        }
    }

    /**
     * @see org.wyona.security.core.api.GroupManager#existsGroup(java.lang.String)
     */
    public boolean existsGroup(String id) throws AccessManagementException {
        return this.groups.containsKey(id);
    }

    /**
     * @see org.wyona.security.core.api.GroupManager#getGroup(java.lang.String)
     */
    public Group getGroup(String id) throws AccessManagementException {
        if (!existsGroup(id)) {
            throw new AccessManagementException("Group " + id + " does not exist.");
        }
        return (Group) this.groups.get(id);
    }

    /**
     * @see org.wyona.security.core.api.GroupManager#getGroups()
     */
    public Group[] getGroups() throws AccessManagementException {
        return (Group[]) this.groups.values().toArray(new Group[this.groups.size()]);
    }

    /**
     * @see org.wyona.security.core.api.GroupManager#removeGroup(java.lang.String)
     */
    public void removeGroup(String id) throws AccessManagementException {
        if (!existsGroup(id)) {
            throw new AccessManagementException("Group " + id + " does not exist.");
        }
        Group group = getGroup(id);
        this.groups.remove(id);
        group.delete();
    }

    /**
     * Gets the repository node which is the parent node of all group nodes.
     * @return parent node of group nodes
     * @throws NoSuchNodeException
     * @throws RepositoryException
     */
    protected Node getGroupsParentNode() throws NoSuchNodeException, RepositoryException {
        if (this.identitiesRepository.existsNode("/groups")) {
            return this.identitiesRepository.getNode("/groups");
        }
        // fallback to root node for backwards compatibility:
        return this.identitiesRepository.getNode("/");    
    }

}