package org.wyona.security.impl;

import org.wyona.security.core.PolicyManagerFactory;
import org.wyona.security.core.api.PolicyManager;

/**
 *
 */
public class PolicyManagerFactoryImpl extends PolicyManagerFactory {

    /**
     *
     */
    public PolicyManager newPolicyManager() {
        return new PolicyManagerImpl();
    }
}
