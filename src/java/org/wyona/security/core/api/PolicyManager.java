package org.wyona.security.core.api;

import org.wyona.commons.io.Path;

/**
 *
 */
public interface PolicyManager {

    /**
     *
     */
    public boolean authorize(Path path, Identity idenitity, Role role);
}
