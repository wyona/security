package org.wyona.security.impl;

import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Policy;

import org.apache.log4j.Logger;

/**
 *
 */
class PolicyImpl implements Policy {

    private static Logger log = Logger.getLogger(PolicyImpl.class);

    /**
     *
     */
    public PolicyImpl(java.io.InputStream in) {
        log.warn("Not implemented yet!");
    }

    public void getUsecases() {
        log.warn("Not implemented yet!");
    }

    public void addUsecase(String usecase) throws AccessManagementException {
        log.warn("Not implemented yet!");
    }

    public Policy getParentPolicy() throws AccessManagementException {
        log.warn("Not implemented yet!");
        return null;
    }
}

