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
        log.error(getPolicyPath(path));
        return true;
    }

    /**
     *
     */
    public Path getPolicyPath(Path path) {
        // Remove trailing slash except for ROOT ...
        String p = path.toString();
        if (p.length() > 1 && p.charAt(p.length() - 1) == '/') {
            return new Path(p.substring(0, p.length() - 1) + ".policy");
        }
        return new Path(p + ".policy");
    }
}
