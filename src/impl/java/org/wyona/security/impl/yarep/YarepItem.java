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

    protected abstract void configure(Configuration config) throws ConfigurationException,
            AccessManagementException;

    /*
     * protected void configure(Configuration config) throws
     * ConfigurationException { this.id = config.getAttribute("id"); this.name =
     * config.getChild("name", false).getValue(); }
     */

    public void delete() throws AccessManagementException {
        try {
            this.node.remove();
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AccessManagementException(e.getMessage(), e);
        }
    }

    public void save() throws AccessManagementException {
        try {
            DefaultConfigurationSerializer serializer = new DefaultConfigurationSerializer();
            Configuration config = createConfiguration();
            serializer.serialize(getNode().getOutputStream(), config);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AccessManagementException(e.getMessage(), e);
        }
    }

    protected abstract Configuration createConfiguration() throws AccessManagementException;

    protected IdentityManager getIdentityManager() {
        return this.identityManager;
    }

    protected Node getNode() {
        return this.node;
    }

    public String getID() {
        return this.id;
    }

    protected void setID(String id) {
        this.id = id;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

}