package org.wyona.security.impl;

import org.w3c.dom.Document;
import org.wyona.security.core.PolicyManagerFactory;
import org.wyona.security.core.api.PolicyManager;
import org.wyona.yarep.core.Repository;

/**
 *
 */
public class PolicyManagerFactoryImpl extends PolicyManagerFactory {

    /**
     *
     */
    public PolicyManager newPolicyManager(Repository policiesRepository) {
        return new PolicyManagerImpl(policiesRepository);
    }

    /**
     *
     */ 
    public PolicyManager newPolicyManager(Document configuration, javax.xml.transform.URIResolver resolver) {
        return null;
    }
}
