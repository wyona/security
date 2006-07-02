package org.wyona.security.impl;

import org.wyona.commons.io.Path;
import org.wyona.security.core.api.Identity;
import org.wyona.security.core.api.PolicyManager;
import org.wyona.security.core.api.Role;
import org.wyona.yarep.core.RepositoryFactory;

import org.apache.log4j.Category;

/**
 *
 */
public class PolicyManagerImpl implements PolicyManager {

    private static Category log = Category.getInstance(PolicyManagerImpl.class);

    private RepositoryFactory repoFactory;

    /**
     *
     */
    public PolicyManagerImpl() {
        try {
            repoFactory = new RepositoryFactory("ac-policies-yarep.properties");
        } catch(Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    /**
     *
     */
    public boolean authorize(Path path, Identity idenitity, Role role) {
        return true;
    }
}
