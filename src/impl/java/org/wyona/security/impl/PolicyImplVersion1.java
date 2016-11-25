package org.wyona.security.impl;

import org.wyona.security.core.GroupPolicy;
import org.wyona.security.core.IdentityPolicy;
import org.wyona.security.core.UsecasePolicy;
import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Group;
import org.wyona.security.core.api.Identity;
import org.wyona.security.core.api.Policy;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.ConfigurationException;
import org.apache.avalon.framework.configuration.DefaultConfigurationBuilder;

import java.util.Vector;

/**
 * @deprecated Because it uses the tag "role" instead "usecase". Use {@link PolicyImplV2} instead.
 */
public class PolicyImplVersion1 implements Policy {

    private static Logger log = LogManager.getLogger(PolicyImplVersion1.class);
    protected DefaultConfigurationBuilder builder = null;
    protected Vector usecasePolicies = null;
    protected boolean useInheritedPolicies = true;

    private static String USECASE_ELEMENT_NAME = "role";

    /**
     *
     */
    public PolicyImplVersion1() throws Exception {
        this.usecasePolicies = new Vector();
    }

    /**
     * Read XML from input stream and create Java object
     * @param in XML as input stream
     */
    public PolicyImplVersion1(java.io.InputStream in) throws Exception {
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
    }

    /**
     *
     */
    public UsecasePolicy[] getUsecasePolicies() {
        UsecasePolicy[] ups = new UsecasePolicy[usecasePolicies.size()];
        for (int i = 0; i < ups.length; i++) {
            ups[i] = (UsecasePolicy) usecasePolicies.elementAt(i);
        }
        return ups;
    }

    /**
     *
     */
    public void addUsecasePolicy(UsecasePolicy up) throws AccessManagementException {
        usecasePolicies.add(up);
    }

    /**
     * @see org.wyona.security.core.api.Policy#getPath()
     */
    public String getPath() throws AccessManagementException {
        log.warn("Not implemented yet!");
        return null;
    }

    /**
     * @see org.wyona.security.core.api.Policy#getParentPolicy()
     */
    public Policy getParentPolicy() throws AccessManagementException {
        log.warn("Not implemented yet!");
        return null;
    }

    /**
     *
     */
    public String toString() {
        StringBuilder sb = new StringBuilder("Policy:\n");
        UsecasePolicy[] ups = getUsecasePolicies();
        for (int i = 0; i < ups.length; i++) {
            sb.append("  Usecase: " + ups[i].getName() + "\n");
            IdentityPolicy[] idps = ups[i].getIdentityPolicies();
            for (int j = 0; j < idps.length; j++) {
                if (idps[j].getIdentity().isWorld()) {
                    sb.append("    WORLD (" + idps[j].getPermission() + ")\n");
                } else {
                    sb.append("    User: " + idps[j].getIdentity().getUsername() + " (" + idps[j].getPermission() + ")\n");
                }
            }
            GroupPolicy[] gps = ups[i].getGroupPolicies();
            for (int j = 0; j < gps.length; j++) {
                sb.append("    Group: " + gps[j].getId() + " (" + gps[j].getPermission() + ")\n");
            }
        }
        return sb.toString();
    }

    /**
     * Read usecase policies from XML
     */
    protected UsecasePolicy readUsecasePolicy(Configuration upConfig) throws Exception {
        UsecasePolicy up = new UsecasePolicy(upConfig.getAttribute("id"));

        up.setUseInheritedPolicies(upConfig.getAttributeAsBoolean("use-inherited-policies", true));

        Configuration[] upConfigs = upConfig.getChildren();
        for (int i = 0; i < upConfigs.length; i++) {
            String upID = upConfigs[i].getName();
            log.debug("Read usecase config: " + upID);
            if (upID.equals("user")) {
                String permission = upConfigs[i].getAttribute("permission", "true");
                String id = upConfigs[i].getAttribute("id");
                up.addIdentity(new Identity(id, id), new Boolean(permission).booleanValue());
            } else if (upID.equals("group")) {
                String permission = upConfigs[i].getAttribute("permission", "true");
                String id = upConfigs[i].getAttribute("id");
                if (permission != null) {
                    up.addGroupPolicy(new GroupPolicy(id, new Boolean(permission).booleanValue()));
                } else {
                    up.addGroupPolicy(new GroupPolicy(id, true));
                }
            } else if (upID.equals("world")) {
                String permission = upConfigs[i].getAttribute("permission", "true");
                up.addIdentity(new Identity(), new Boolean(permission).booleanValue());
            } else {
                log.error("No such usecase type implemented: " + upID);
            }
        }
            
/* DEPRECATED
        Configuration[] worldConfigs = upConfig.getChildren("world");
        if (worldConfigs.length > 1) log.warn("Usecase policy contains more than one WORLD entry!");
        for (int j = 0; j < worldConfigs.length; j++) {
            String permission = worldConfigs[j].getAttribute("permission", "true");
            up.addIdentity(new Identity(), new Boolean(permission).booleanValue());
        }

        Configuration[] userConfigs = upConfig.getChildren("user");
        for (int j = 0; j < userConfigs.length; j++) {
            String permission = userConfigs[j].getAttribute("permission", "true");
            String id = userConfigs[j].getAttribute("id");
            up.addIdentity(new Identity(id, id), new Boolean(permission).booleanValue());
        }

        Configuration[] groupConfigs = upConfig.getChildren("group");
        for (int j = 0; j < groupConfigs.length; j++) {
            String permission = groupConfigs[j].getAttribute("permission", "true");
            String id = groupConfigs[j].getAttribute("id");
            if (permission != null) {
                up.addGroupPolicy(new GroupPolicy(id, new Boolean(permission).booleanValue()));
            } else {
                up.addGroupPolicy(new GroupPolicy(id, true));
            }
        }
*/

        return up;
    }

    /**
     *
     */
    public boolean useInheritedPolicies() {
        return useInheritedPolicies;
    }

    public void setUseInheritedPolicies(boolean useInheritedPolicies) {
        this.useInheritedPolicies = useInheritedPolicies;
    }
    
    public void removeUsecasePolicy(String name) throws AccessManagementException {
        for (int i = 0; i < usecasePolicies.size(); i++) {
            UsecasePolicy up = (UsecasePolicy)usecasePolicies.elementAt(i);
            if (up.getName().equals(name)) {
                usecasePolicies.remove(i);
                return;
            }
        }
    }

    /**
     *
     */
    public UsecasePolicy getUsecasePolicy(String name) throws AccessManagementException {
        for (int i = 0; i < usecasePolicies.size(); i++) {
            UsecasePolicy up = (UsecasePolicy)usecasePolicies.elementAt(i);
            if (up.getName().equals(name)) {
                return (UsecasePolicy)usecasePolicies.elementAt(i);
            }
        }
        return null;
    }

    /**
     * @see java.lang.Object#equals(Object)
     */
    public boolean equals(Object object) {
        log.warn("Check whether these two policies are equal...");
        Policy thatPolicy = (Policy) object;

        UsecasePolicy[] upsOfThis = getUsecasePolicies();
        for (int i = 0; i < upsOfThis.length; i++) {
            try {
                if (thatPolicy.getUsecasePolicy(upsOfThis[i].getName()) == null) {
                    log.warn("That policy does not contain usecase '" + upsOfThis[i].getName() + "' of this policy!");
                    return false;
                }
            } catch(Exception e) {
                log.warn(e.getMessage());
                return false;
            }
        }

        UsecasePolicy[] upsOfThat = thatPolicy.getUsecasePolicies();
        for (int i = 0; i < upsOfThat.length; i++) {
            try {
                if (getUsecasePolicy(upsOfThat[i].getName()) == null) {
                    log.warn("This policy does not contain usecase '" + upsOfThat[i].getName() + "' of that policy!");
                    return false;
                }
            } catch(Exception e) {
                log.warn(e.getMessage());
                return false;
            }
        }

        log.warn("Both policies seem to have same usecase policies, therefore compare these usecase policies individually...");

        for (int i = 0; i < upsOfThis.length; i++) {
            try {
                if (!upsOfThis[i].equals(thatPolicy.getUsecasePolicy(upsOfThis[i].getName()))) {
                    return false;
                }
            } catch(Exception e) {
                log.warn(e.getMessage());
                return false;
            }
        }

        return true;
    }
}
