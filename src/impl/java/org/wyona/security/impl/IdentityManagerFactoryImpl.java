package org.wyona.security.impl;

import org.wyona.security.core.IdentityManagerFactory;
import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.yarep.core.Repository;

import org.apache.log4j.Category;

/**
 *
 */
public class IdentityManagerFactoryImpl extends IdentityManagerFactory {

    private static Category log = Category.getInstance(IdentityManagerFactoryImpl.class);

    /**
     *
     */
    public IdentityManager newIdentityManager(Repository identitiesRepository) {
        IdentityManager im = null;
        try {
            im = new org.wyona.security.impl.yarep.YarepIdentityManagerImpl(identitiesRepository);
        } catch (AccessManagementException e) {
            log.error(e, e);
        }
        return im;
    }

    /**
     *
     */
    public IdentityManager newIdentityManager(org.w3c.dom.Document configuration, javax.xml.transform.URIResolver resolver) {
        log.error("Not implemented yet!");
        return null;
    }
}
