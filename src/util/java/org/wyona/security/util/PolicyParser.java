package org.wyona.security.util;

import org.wyona.security.core.GroupPolicy;
import org.wyona.security.core.UsecasePolicy;
import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Group;
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
public class PolicyParser implements Policy {

    private static Logger log = Logger.getLogger(PolicyParser.class);
    protected DefaultConfigurationBuilder builder = null;
    protected Vector usecasePolicies = null;
    protected boolean useInheritedPolicies = true;

    private static String USECASE_ELEMENT_NAME = "role";

    /**
     *
     */
    public PolicyParser() throws Exception {
    }

    /**
     *
     */
    public Policy parseXML(java.io.InputStream in) throws Exception {
/*
        boolean enableNamespaces = true;
        builder = new DefaultConfigurationBuilder(enableNamespaces);
        Configuration config = builder.build(in);

        String useInheritedPoliciesString = config.getAttribute("use-inherited-policies", "true");
        if (useInheritedPoliciesString.equals("false")) useInheritedPolicies = false;

        Configuration[] upConfigs = config.getChildren(USECASE_ELEMENT_NAME);
        usecasePolicies = new Vector();
        for (int i = 0; i < upConfigs.length; i++) {
            usecasePolicies.add(readUsecasePolicy(upConfigs[i]));
        }
*/
        return this;
    }

    /**
     * @see
     */
    public UsecasePolicy[] getUsecasePolicies() {
        UsecasePolicy[] ups = new UsecasePolicy[usecasePolicies.size()];
        for (int i = 0; i < ups.length; i++) {
            ups[i] = (UsecasePolicy) usecasePolicies.elementAt(i);
        }
        return ups;
    }

    /**
     * @see
     */
    public void addUsecasePolicy(UsecasePolicy up) throws AccessManagementException {
        usecasePolicies.add(up);
        log.warn("Usecase policy has been added: " + up.getName());
    }

    /**
     * @see
     */
    public Policy getParentPolicy() throws AccessManagementException {
        log.warn("Not implemented yet!");
        return null;
    }

    /**
     * @see
     */
    public boolean useInheritedPolicies() {
        return useInheritedPolicies;
    }

    /**
     *
     */
/*
    protected UsecasePolicy readUsecasePolicy(Configuration upConfig) throws Exception {
            UsecasePolicy up = new UsecasePolicy(upConfig.getAttribute("id"));

            Configuration[] worldConfigs = upConfig.getChildren("world");
            if (worldConfigs.length > 1) log.warn("Usecase policy contains more than one WORLD entry!");
            for (int j = 0; j < worldConfigs.length; j++) {
                up.addIdentity(new Identity());
            }

            Configuration[] userConfigs = upConfig.getChildren("user");
            for (int j = 0; j < userConfigs.length; j++) {
                up.addIdentity(new Identity(userConfigs[j].getAttribute("id"), null));
            }

            Configuration[] groupConfigs = upConfig.getChildren("group");
            for (int j = 0; j < groupConfigs.length; j++) {
                String permission = groupConfigs[j].getAttribute("permission");
                String id = groupConfigs[j].getAttribute("id");
                if (permission != null) {
                    up.addGroupPolicy(new GroupPolicy(id, getBoolean(permission)));
                } else {
                    up.addGroupPolicy(new GroupPolicy(id));
                }
            }
        return up;
    }
*/

    /**
     *
     */
/*
    private boolean getBoolean(String value) {
        if (value.equals("false")) {
            return false;
        } else if (value.equals("true")) {
            return true;
        } else {
            log.error("No such boolean value: " + value);
            return false;
        }
    }
*/

    public String toString() {
        StringBuffer sb = new StringBuffer("Policy:\n");
        UsecasePolicy[] ups = getUsecasePolicies();
        for (int i = 0; i < ups.length; i++) {
            sb.append("  Usecase: " + ups[i].getName() + "\n");
            Identity[] ids = ups[i].getIdentities();
            for (int j = 0; j < ids.length; j++) {
                if (ids[j].isWorld()) {
                    sb.append("    WORLD\n");
                } else {
                    sb.append("    User: " + ids[j].getUsername() + "\n");
                }
            }
            GroupPolicy[] gps = ups[i].getGroupPolicies();
            for (int j = 0; j < gps.length; j++) {
                sb.append("    Group: " + gps[j].getId() + " (" + gps[j].getPermission() + ")\n");
            }
        }
        return sb.toString();
    }
}

