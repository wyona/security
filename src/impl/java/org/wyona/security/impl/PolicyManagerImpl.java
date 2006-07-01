package org.wyona.security.impl;

import org.wyona.commons.io.Path;
import org.wyona.security.core.api.Identity;
import org.wyona.security.core.api.PolicyManager;
import org.wyona.security.core.api.Role;

/**
 *
 */
public class PolicyManagerImpl implements PolicyManager {

    /**
     *
     */
    public boolean authorize(Path path, Identity idenitity, Role role) {
        return true;
    }
}
