package org.wyona.security.impl;

import org.wyona.security.core.UsecasePolicy;
import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Policy;

import org.apache.log4j.Logger;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.ConfigurationException;
import org.apache.avalon.framework.configuration.DefaultConfigurationBuilder;

import java.util.Vector;

/**
 *
 */
public class PolicyImplV2 extends PolicyImplVersion1 {

    private static Logger log = Logger.getLogger(PolicyImplV2.class);

    /**
     *
     */
    public PolicyImplV2() throws Exception {
    }

    /**
     *
     */
    public PolicyImplV2(java.io.InputStream in) throws Exception {
        log.warn("Implementation not finished yet!");
        boolean enableNamespaces = true;
        builder = new DefaultConfigurationBuilder(enableNamespaces);
        Configuration config = builder.build(in);
        Configuration[] upConfigs = config.getChildren("usecase");
        usecasePolicies = new Vector();
        for (int i = 0; i < upConfigs.length; i++) {
            usecasePolicies.add(readUsecasePolicy(upConfigs[i]));
        }
    }
}

