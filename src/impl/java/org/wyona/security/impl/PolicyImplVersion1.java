package org.wyona.security.impl;

import org.wyona.security.core.UsecasePolicy;
import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Identity;
import org.wyona.security.core.api.Policy;

import org.apache.log4j.Logger;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.ConfigurationException;
import org.apache.avalon.framework.configuration.DefaultConfigurationBuilder;

import java.util.Vector;

/**
 *
 */
public class PolicyImplVersion1 implements Policy {

    private static Logger log = Logger.getLogger(PolicyImplVersion1.class);
    protected DefaultConfigurationBuilder builder = null;
    protected Vector usecasePolicies = null;

    /**
     *
     */
    public PolicyImplVersion1() throws Exception {
    }

    /**
     *
     */
    public PolicyImplVersion1(java.io.InputStream in) throws Exception {
        log.warn("Implementation not finished yet!");
        boolean enableNamespaces = true;
        builder = new DefaultConfigurationBuilder(enableNamespaces);
        Configuration config = builder.build(in);

        Configuration[] upConfigs = config.getChildren("role");
        usecasePolicies = new Vector();
        for (int i = 0; i < upConfigs.length; i++) {
            UsecasePolicy up = new UsecasePolicy(upConfigs[i].getAttribute("id"));
            Configuration[] worldConfigs = upConfigs[i].getChildren("world");
            if (worldConfigs.length > 1) log.warn("Usecase policy contains more than one WORLD entry!");
            for (int j = 0; j < worldConfigs.length; j++) {
                up.addIdentity(new Identity());
            }
            Configuration[] userConfigs = upConfigs[i].getChildren("user");
            for (int j = 0; j < userConfigs.length; j++) {
                up.addIdentity(new Identity(userConfigs[j].getAttribute("id"), null));
            }
/*
            Configuration[] groupConfigs = upConfigs[i].getChildren("group");
            for (int j = 0; j < groupConfigs.length; j++) {
                up.addIdentity(new Identity());
            }
*/

            usecasePolicies.add(up);
        }
    }

    public UsecasePolicy[] getUsecasePolicies() {
        UsecasePolicy[] ups = new UsecasePolicy[usecasePolicies.size()];
        for (int i = 0; i < ups.length; i++) {
            ups[i] = (UsecasePolicy) usecasePolicies.elementAt(i);
        }
        return ups;
    }

    public void addUsecasePolicy(UsecasePolicy up) throws AccessManagementException {
        log.warn("Not implemented yet!");
    }

    public Policy getParentPolicy() throws AccessManagementException {
        log.warn("Not implemented yet!");
        return null;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer("Policy:\n");
        UsecasePolicy[] ups = getUsecasePolicies();
        for (int i = 0; i < ups.length; i++) {
            sb.append("Usecase: " + ups[i].getName() + "\n");
            Identity[] ids = ups[i].getIdentities();
            for (int j = 0; j < ids.length; j++) {
                if (ids[j].isWorld()) {
                    sb.append("WORLD\n");
                } else {
                    sb.append("User: " + ids[j].getUsername() + "\n");
                }
            }
        }
        return sb.toString();
    }
}

