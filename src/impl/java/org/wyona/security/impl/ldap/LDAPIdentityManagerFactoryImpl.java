package org.wyona.security.impl.ldap;

import org.wyona.security.core.IdentityManagerFactory;
import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.yarep.core.Repository;

import org.apache.log4j.Logger;

/**
 * Factory in order to get LDAP implementation
 */
public class LDAPIdentityManagerFactoryImpl extends IdentityManagerFactory {

    private static Logger log = Logger.getLogger(LDAPIdentityManagerFactoryImpl.class);

    /**
     * @see org.wyona.security.core.IdentityManagerFactory#newIdentityManager(Repository)
     */
    public IdentityManager newIdentityManager(Repository identitiesRepository) throws UnsupportedOperationException {
        throw new UnsupportedOperationException("This operation should never be called");
    }

    /**
     * @see org.wyona.security.core.IdentityManagerFactory#newIdentityManager(Document, URIResolver)
     */
    public IdentityManager newIdentityManager(org.w3c.dom.Document configuration, javax.xml.transform.URIResolver resolver) {
        try {
            boolean load = false;
            return new org.wyona.security.impl.ldap.LDAPIdentityManagerImpl(getRepository(configuration), load);
        } catch (AccessManagementException e) {
            log.error(e, e);
        }
        return null;
    }

    /**
     * Get Yarep repository
     * @param configuration XML configuration, e.g. <identity-manager-config xmlns="http://www.wyona.org/security/1.0">config/ac-identities-repository.xml</identity-manager-config>
     */
    private Repository getRepository(org.w3c.dom.Document configuration) {
        log.warn("DEBUG: Configuration: " + org.wyona.commons.xml.XMLHelper.documentToString(configuration, false, true, null));
        return null;
    }
}
