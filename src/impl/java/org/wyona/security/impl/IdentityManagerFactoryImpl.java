package org.wyona.security.impl;

import org.wyona.security.core.IdentityManagerFactory;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.yarep.core.Repository;

/**
 *
 */
public class IdentityManagerFactoryImpl extends IdentityManagerFactory {

    /**
     *
     */
    public IdentityManager newIdentityManager(Repository identitiesRepository) {
        return new IdentityManagerImpl(identitiesRepository);
    }

    /**
     *
     */
    public IdentityManager newIdentityManager(org.w3c.dom.Document configuration, javax.xml.transform.URIResolver resolver) {
        return null;
    }
}
