package org.wyona.security.impl.yarep;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.ConfigurationException;
import org.apache.avalon.framework.configuration.DefaultConfigurationBuilder;
import org.apache.avalon.framework.configuration.DefaultConfigurationSerializer;

import org.apache.log4j.Logger;

import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.GroupManager;
import org.wyona.security.core.api.Item;
import org.wyona.security.core.api.UserManager;

import org.wyona.yarep.core.Node;
import org.wyona.yarep.core.NodeType;
import org.wyona.yarep.core.RepositoryException;

/**
 * Methods which have YarepUser and YarepGroup in common
 */
public abstract class YarepItem implements Item {

    private UserManager userManager;
    private GroupManager groupManager;

    private static Logger log = Logger.getLogger(YarepItem.class);
    
    protected static final String NAME = "name";

    public static final String ID = "id";

    private String id;

    private String name;

    private Node node;

    /**
     * Instantiates an existing YarepItem from a repository node.
     *
     * @param userManager
     * @param groupManager
     * @param node
     * @throws AccessManagementException
     */
    public YarepItem(UserManager userManager, GroupManager groupManager, Node node) throws AccessManagementException {
        this.userManager = userManager;
        this.groupManager = groupManager;
        try {
            this.node = node;
            DefaultConfigurationBuilder configBuilder = new DefaultConfigurationBuilder(true);
            if (log.isDebugEnabled()) log.debug("Read/Load item (either user or group) from repo node: " + node.getPath());
            Configuration config = configBuilder.build(node.getInputStream());
            configure(config);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AccessManagementException(e.getMessage(), e);
        }
    }

    /**
     * Creates a new YarepItem with a given id and name (not persistent)
     *
     * @param userManager
     * @param groupManager
     * @param id
     * @param name
     */
    public YarepItem(UserManager userManager, GroupManager groupManager, String id, String name) {
        this.userManager = userManager;
        this.groupManager = groupManager;
        this.id = id;
        this.name = name;
    }

    /**
     * Reads the configuration for this item and sets the fields.
     * 
     * @param config
     * @throws ConfigurationException
     * @throws AccessManagementException
     */
    protected abstract void configure(Configuration config) throws ConfigurationException, AccessManagementException;

    /**
     * Creates a configuration object of this item.
     * This object could be used to save this item.
     * 
     * @return configuration
     * @throws AccessManagementException
     */
    protected abstract Configuration createConfiguration() throws AccessManagementException;

    /**
     * @see org.wyona.security.core.api.Item#delete()
     */
    public void delete() throws AccessManagementException {
        try {
            this.node.delete();
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AccessManagementException(e.getMessage(), e);
        }
    }

    /**
     * @see org.wyona.security.core.api.Item#save()
     */
    public void save() throws AccessManagementException {
        try {
            DefaultConfigurationSerializer serializer = new DefaultConfigurationSerializer();
            Configuration config = createConfiguration();
            serializer.setIndent(true);
            getNode().setMimeType("application/xml");
            java.io.OutputStream out = getNode().getOutputStream();
            serializer.serialize(out, config);
            out.close();
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AccessManagementException(e.getMessage(), e);
        }
    }

    /**
     * Gets the repository node which contains the configuration of this item.
     * @return node
     */
    protected Node getNode() {
        return this.node;
    }
    
    /**
     * Sets the repository node which shall contain the configuration of this item.
     * @param node Yarep repository node
     */
    public void setNode(Node node) {
        this.node = node;
    }

    /**
     * @see org.wyona.security.core.api.Item#getID()
     */
    public String getID() throws AccessManagementException{
        return this.id;
    }

    /**
     * Sets the id of this item.
     * @param id
     */
    protected void setID(String id) throws AccessManagementException{
        this.id = id;
    }

    /**
     * @see org.wyona.security.core.api.Item#getName()
     */
    public String getName() throws AccessManagementException{
        return this.name;
    }

    /**
     * @see org.wyona.security.core.api.Item#setName(java.lang.String)
     */
    public void setName(String name) throws AccessManagementException{
        this.name = name;
    }

    /**
     *
     */
    public UserManager getUserManager() {
        return this.userManager;
    }

    /**
     *
     */
    public GroupManager getGroupManager() {
        return this.groupManager;
    }
}
