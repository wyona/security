package org.wyona.security.impl.yarep;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.ConfigurationException;
import org.apache.avalon.framework.configuration.DefaultConfigurationBuilder;
import org.apache.avalon.framework.configuration.DefaultConfigurationSerializer;
import org.apache.log4j.Category;
import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.security.core.api.Item;
import org.wyona.yarep.core.Node;
import org.wyona.yarep.core.NodeType;
import org.wyona.yarep.core.RepositoryException;

public abstract class YarepItem implements Item {
    private static Category log = Category.getInstance(YarepItem.class);

    public static final String NAME = "name";

    public static final String ID = "id";

    protected String id;

    protected String name;

    protected Node node;

    protected IdentityManager identityManager;

    /**
     * Instantiates an existing YarepItem from a repository node.
     *
     * @param identityManager
     * @param node
     * @throws AccessManagementException
     */
    public YarepItem(IdentityManager identityManager, Node node) throws AccessManagementException {
        try {
            this.identityManager = identityManager;
            this.node = node;
            DefaultConfigurationBuilder configBuilder = new DefaultConfigurationBuilder(true);
            Configuration config = configBuilder.build(node.getInputStream());
            configure(config);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AccessManagementException(e.getMessage(), e);
        }
    }

    /**
     * Creates a new YarepItem with the given id as a child of the given parent
     * node. The item is not saved.

     * @param identityManager
     * @param parentNode
     * @param id
     * @param name
     * @param nodeName
     * @throws AccessManagementException
     */
    public YarepItem(IdentityManager identityManager, Node parentNode, String id, String name, 
            String nodeName)
            throws AccessManagementException {
        this.identityManager = identityManager;
        this.id = id;
        this.name = name;
        try {
            this.node = parentNode.addNode(nodeName, NodeType.RESOURCE);
        } catch (RepositoryException e) {
            log.error(e.getMessage(), e);
            throw new AccessManagementException(e.getMessage(), e);
        }
    }

    /**
     * Reads the configuration for this item and sets the fields.
     * 
     * @param config
     * @throws ConfigurationException
     * @throws AccessManagementException
     */
    protected abstract void configure(Configuration config) throws ConfigurationException,
            AccessManagementException;

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
            this.node.remove();
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
            serializer.serialize(getNode().getOutputStream(), config);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AccessManagementException(e.getMessage(), e);
        }
    }

    /**
     * Gets the identity manager which belongs to this item.
     * @return identity manager
     */
    protected IdentityManager getIdentityManager() {
        return this.identityManager;
    }

    /**
     * Gets the repository node which contains the configuration of this item.
     * @return node
     */
    protected Node getNode() {
        return this.node;
    }

    /**
     * @see org.wyona.security.core.api.Item#getID()
     */
    public String getID() {
        return this.id;
    }

    /**
     * Sets the id of this item.
     * @param id
     */
    protected void setID(String id) {
        this.id = id;
    }

    /**
     * @see org.wyona.security.core.api.Item#getName()
     */
    public String getName() {
        return this.name;
    }

    /**
     * @see org.wyona.security.core.api.Item#setName(java.lang.String)
     */
    public void setName(String name) {
        this.name = name;
    }

}