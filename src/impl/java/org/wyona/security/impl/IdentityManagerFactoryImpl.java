package org.wyona.security.impl;

import org.wyona.security.core.IdentityManagerFactory;
import org.wyona.security.core.api.IdentityManager;

/**
 *
 */
public class IdentityManagerFactoryImpl extends IdentityManagerFactory {

    /**
     *
     */
    public IdentityManager newIdentityManager() {
        return new IdentityManagerImpl();
    }
}
