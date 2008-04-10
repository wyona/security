package org.wyona.security.core;

import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Identity;
import org.wyona.security.core.GroupPolicy;

import java.util.Vector;

import org.apache.log4j.Logger;

/**
 *
 */
public class UsecasePolicy {

    private static Logger log = Logger.getLogger(UsecasePolicy.class);

    private String name;

    private Vector idps = null;
    private Vector gps = null;
    private boolean useInheritedPolicies = true;

    /**
     *
     */
    public UsecasePolicy(String name) {
        this.name = name;
        idps = new Vector();
        gps = new Vector();
    }

    /**
     *
     */
    public String getName() {
        return name;
    }

    /**
     *
     */
    public void addIdentity(Identity identity, boolean permission) {
        idps.add(new IdentityPolicy(identity, permission));
    }

    /**
     *
     */
    public Identity[] getIdentities() {
        Identity[] ids = new Identity[idps.size()];
        for (int i = 0; i < ids.length; i++) {
            ids[i] = ((IdentityPolicy) idps.elementAt(i)).getIdentity();
        }
        return ids;
    }

    /**
     *
     */
    public IdentityPolicy[] getIdentityPolicies() {
        IdentityPolicy[] ip = new IdentityPolicy[idps.size()];
        for (int i = 0; i < ip.length; i++) {
            ip[i] = (IdentityPolicy) idps.elementAt(i);
        }
        return ip;
    }
    
    /**
     * Gets the identity policy for the given identity or null if there is no such
     * identity policy. 
     * @param identity
     * @return identity policy or null
     */
    public IdentityPolicy getIdentityPolicy(Identity identity) {
        for (int i = 0; i < idps.size(); i++) {
            IdentityPolicy ip = (IdentityPolicy)idps.elementAt(i);
            if (identity.isWorld() && ip.getIdentity().isWorld() ||
                    identity.getUsername().equals(ip.getIdentity().getUsername())) {
                return ip;
            }
        }
        return null;
    }
    
    /**
     * Removes an identity policy from this usecase policy.
     * Does not do anything if this policy has no identity policy for the given identity.
     * The modification is not persistent, it only modifies the policy object in the memory.  
     * @param identity
     */
    public void removeIdentityPolicy(Identity identity) {
        for (int i = 0; i < idps.size(); i++) {
            IdentityPolicy ip = (IdentityPolicy)idps.elementAt(i);
            if (identity.isWorld() && ip.getIdentity().isWorld() ||
                    identity.getUsername().equals(ip.getIdentity().getUsername())) {
                idps.remove(i);
                return;
            }
        }
    }

    /**
     *
     */
    public void addGroupPolicy(GroupPolicy groupPolicy) {
        gps.add(groupPolicy);
    }

    /**
     *
     */
    public GroupPolicy[] getGroupPolicies() {
        GroupPolicy[] gs = new GroupPolicy[gps.size()];
        for (int i = 0; i < gs.length; i++) {
            gs[i] = (GroupPolicy) gps.elementAt(i);
        }
        return gs;
    }

    /**
     * Gets the group policy for the given group id or null if there is no such
     * group policy.
     * @param groupId
     * @return group policy or null
     */
    public GroupPolicy getGroupPolicy(String groupId) {
        for (int i = 0; i < gps.size(); i++) {
            GroupPolicy gp = (GroupPolicy)gps.elementAt(i);
            if (groupId.equals(gp.getId())) {
                return gp;
            }
        }
        return null;
    }

    /**
     * Removes an group policy from this usecase policy.
     * Does not do anything if this policy has no group policy for the given group id.
     * The modification is not persistent, it only modifies the policy object in the memory.  
     * @param groupId 
     */
    public void removeGroupPolicy(String groupId) {
        for (int i = 0; i < gps.size(); i++) {
            GroupPolicy gp = (GroupPolicy)gps.elementAt(i);
            if (groupId.equals(gp.getId())) {
                gps.remove(i);
                return;
            }
        }
    }

    /**
     * Check if inheritance shall be applied.
     *
     */
    public boolean useInheritedPolicies() {
        return useInheritedPolicies;
    }
    
    /**
     * Set if inheritance shall be applied.
     * The default is true.
     * @param useInheritedPolicies
     */
    public void setUseInheritedPolicies(boolean useInheritedPolicies) {
        this.useInheritedPolicies = useInheritedPolicies;
    }

    
    /**
     * Merge UsecasePolicy into this UsecasePolicy
     */
    public void merge(UsecasePolicy up) {
        if (!getName().equals(up.getName())) {
            log.error("Usecase policies do not have the same names: " + getName() + " != " + up.getName());
            return;
        }

        // Merge identities
        IdentityPolicy[] upIdps = up.getIdentityPolicies();
        for (int i = 0; i < upIdps.length; i++) {
            boolean identityAlreadyExists = false;
            for (int k = 0; k < idps.size(); k++) {
                if (((IdentityPolicy) idps.elementAt(k)).getIdentity().getUsername().equals(upIdps[i].getIdentity().getUsername())) {
                    identityAlreadyExists = true;
                    break;
                }
            }
            if (!identityAlreadyExists) {
                addIdentity(upIdps[i].getIdentity(), upIdps[i].getPermission());
            }
        }

        // Merge groups
        GroupPolicy[] upGps = up.getGroupPolicies();
        for (int i = 0; i < upGps.length; i++) {
            boolean groupAlreadyExists = false;
            for (int k = 0; k < gps.size(); k++) {
                if (((GroupPolicy) gps.elementAt(k)).getId().equals(upGps[i].getId())) {
                    groupAlreadyExists = true;
                    break;
                }
            }
            if (!groupAlreadyExists) {
                addGroupPolicy(upGps[i]);
            }
        }
    }
}
