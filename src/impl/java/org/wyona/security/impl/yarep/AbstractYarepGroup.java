package org.wyona.security.impl.yarep;

import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Group;
import org.wyona.security.core.api.GroupManager;
import org.wyona.security.core.api.Item;
import org.wyona.security.core.api.UserManager;

import org.wyona.yarep.core.Node;

import org.apache.log4j.Logger;

/**
 * Abstract Yarep Group providing basic information and access
 */
public abstract class AbstractYarepGroup {

    private static final Logger log = Logger.getLogger(AbstractYarepGroup.class);

    protected String id;
    protected String name;
    protected GroupManager groupManager;
    protected UserManager userManager;

    protected Node node;

    /**
     *
     */
    public void setID(String id) {
        this.id = id;
    }

    /**
     *
     */
    public void setGroupManager(GroupManager groupManager) {
        this.groupManager = groupManager;
    }

    /**
     *
     */
    public void setUserManager(UserManager userManager) {
        this.userManager = userManager;
    }

    /**
     *
     */
    public void setNode(Node node) {
        this.node = node;
    }
}
