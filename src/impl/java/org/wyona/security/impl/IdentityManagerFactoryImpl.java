package org.wyona.security.impl;

import org.wyona.security.core.IdentityManagerFactory;
import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.yarep.core.Repository;

import org.apache.log4j.Logger;

/**
 *
 */
public class IdentityManagerFactoryImpl extends IdentityManagerFactory {

    private static Logger log = Logger.getLogger(IdentityManagerFactoryImpl.class);

    /**
     * @see org.wyona.security.core.IdentityManagerFactory#newIdentityManager(Repository)
     */
    public IdentityManager newIdentityManager(Repository identitiesRepository) {
        IdentityManager im = null;
        try {
            boolean load = false;
            im = new org.wyona.security.impl.yarep.YarepIdentityManagerImpl(identitiesRepository, load);
        } catch (AccessManagementException e) {
            log.error(e, e);
        }
        return im;
    }

    /**
     * @see org.wyona.security.core.IdentityManagerFactory#newIdentityManager(org.w3c.dom.Document, javax.xml.transform.URIResolver)
     */
    public IdentityManager newIdentityManager(org.w3c.dom.Document configuration, javax.xml.transform.URIResolver resolver) {
        try {
            boolean load = false;
            return new org.wyona.security.impl.yarep.YarepIdentityManagerImpl(configuration, resolver, load);
        } catch (AccessManagementException e) {
            log.error(e, e);
            return null;
        }
    }
}
