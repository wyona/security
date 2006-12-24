package org.wyona.security.core.api;

import org.wyona.commons.io.Path;
import org.wyona.security.core.AuthorizationException;
import org.wyona.yarep.core.Repository;

/**
 *
 */
public interface PolicyManager {

    /**
     *
     */
    public boolean authorize(Path path, Identity idenitity, Role role) throws AuthorizationException;
    
}
