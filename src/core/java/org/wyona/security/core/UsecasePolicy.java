package org.wyona.security.core;

import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Identity;
import org.wyona.security.core.GroupPolicy;

import java.util.Vector;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

/**
 * Uscase policy containing
 */
public class UsecasePolicy {

    private static Logger log = Logger.getLogger(UsecasePolicy.class);

    private String name;

/* DEPRECATED
    private Vector idps = null;
    private Vector gps = null;
*/
    private List userOrGroupPolicies = null;
    private boolean useInheritedPolicies = true;

    /**
     *
     */
    public UsecasePolicy(String name) {
        this.name = name;
/* DEPRECATED
        idps = new Vector();
        gps = new Vector();
*/
        userOrGroupPolicies = new ArrayList();
    }

    /**
     * Get name/ID of usecase
     */
    public String getName() {
        return name;
    }

    /**
     * Add "user" policy
     * @param identity Identity, e.g. a user@param identity Identity, e.g. a user
     */
    public void addIdentity(Identity identity, boolean permission) {
        userOrGroupPolicies.add(new IdentityPolicy(identity, permission));

        // DEPRECATED
        //idps.add(new IdentityPolicy(identity, permission));
    }

    /**
     * Get all identities of this usecase policy
     */
    public Identity[] getIdentities() {
        ArrayList ids = new ArrayList();
        for (int i = 0; i < userOrGroupPolicies.size(); i++) {
            if (userOrGroupPolicies.get(i) instanceof IdentityPolicy) {
                ids.add(((IdentityPolicy)userOrGroupPolicies.get(i)).getIdentity());
            }
        }
        return (Identity[])ids.toArray(new Identity[ids.size()]);

/* DEPRECATED
        Identity[] ids = new Identity[idps.size()];
        for (int i = 0; i < ids.length; i++) {
            ids[i] = ((IdentityPolicy) idps.elementAt(i)).getIdentity();
        }
        return ids;
*/
    }

    /**
     * Get all identity policies of this usecase policy
     */
    public IdentityPolicy[] getIdentityPolicies() {
        ArrayList idPolicies = new ArrayList();
        for (int i = 0; i < userOrGroupPolicies.size(); i++) {
            if (userOrGroupPolicies.get(i) instanceof IdentityPolicy) {
                idPolicies.add((IdentityPolicy)userOrGroupPolicies.get(i));
            }
        }
        //log.debug("Number of identity policies: " + idPolicies.size());
        return (IdentityPolicy[])idPolicies.toArray(new IdentityPolicy[idPolicies.size()]);

/* DEPRECATED
        IdentityPolicy[] ip = new IdentityPolicy[idps.size()];
        for (int i = 0; i < ip.length; i++) {
            ip[i] = (IdentityPolicy) idps.elementAt(i);
        }
        return ip;
*/
    }
    
    /**
     * Gets the identity policy for the given identity or null if there is no such
     * identity policy. 
     * @param identity
     * @return identity policy or null
     */
    public IdentityPolicy getIdentityPolicy(Identity identity) {
        for (int i = 0; i < userOrGroupPolicies.size(); i++) {
            if (userOrGroupPolicies.get(i) instanceof IdentityPolicy) {
                IdentityPolicy ip = (IdentityPolicy)userOrGroupPolicies.get(i);
                if (identity.isWorld() && ip.getIdentity().isWorld() || identity.getUsername().equals(ip.getIdentity().getUsername())) {
                    return ip;
                }
            }
        }
        log.debug("No such identity policy for user: " + identity.getUsername());
        return null;
    }
    
    /**
     * Removes an identity policy from this usecase policy.
     * Does not do anything if this policy has no identity policy for the given identity.
     * The modification is not persistent, it only modifies the policy object in the memory.  
     * @param identity
     */
    public void removeIdentityPolicy(Identity identity) {
        for (int i = 0; i < userOrGroupPolicies.size(); i++) {
            if (userOrGroupPolicies.get(i) instanceof IdentityPolicy) {
                IdentityPolicy ip = (IdentityPolicy)userOrGroupPolicies.get(i);
                if (identity.isWorld() && ip.getIdentity().isWorld() || identity.getUsername().equals(ip.getIdentity().getUsername())) {
                    userOrGroupPolicies.remove(i);
                    return;
                }
            }
        }
        log.warn("No such identity: " + identity.getUsername());
/* DEPRECATED
        for (int i = 0; i < idps.size(); i++) {
            IdentityPolicy ip = (IdentityPolicy)idps.elementAt(i);
            if (identity.isWorld() && ip.getIdentity().isWorld() ||
                    identity.getUsername().equals(ip.getIdentity().getUsername())) {
                idps.remove(i);
                return;
            }
        }
*/
    }

    /**
     * Add group policy
     *
     * @param groupPolicy Group policy
     */
    public void addGroupPolicy(GroupPolicy groupPolicy) {
        userOrGroupPolicies.add(groupPolicy);
    }

    /**
     * Get group policies
     */
    public GroupPolicy[] getGroupPolicies() {
        ArrayList groupPolicies = new ArrayList();
        for (int i = 0; i < userOrGroupPolicies.size(); i++) {
            if (userOrGroupPolicies.get(i) instanceof GroupPolicy) {
                groupPolicies.add((GroupPolicy)userOrGroupPolicies.get(i));
            }
        }
        return (GroupPolicy[])groupPolicies.toArray(new GroupPolicy[groupPolicies.size()]);

/* DEPRECATED
        GroupPolicy[] gs = new GroupPolicy[gps.size()];
        for (int i = 0; i < gs.length; i++) {
            gs[i] = (GroupPolicy) gps.elementAt(i);
        }
        return gs;
*/
    }

    /**
     * Gets the group policy for the given group id or null if there is no such
     * group policy.
     * @param groupId
     * @return group policy or null
     */
    public GroupPolicy getGroupPolicy(String groupId) {
        for (int i = 0; i < userOrGroupPolicies.size(); i++) {
            if (userOrGroupPolicies.get(i) instanceof GroupPolicy) {
                GroupPolicy gp = (GroupPolicy)userOrGroupPolicies.get(i);
                if (groupId.equals(gp.getId())) {
                    return gp;
                }
            }
        }
        log.debug("No group policy exists for group: " + groupId);
        return null;
    }

    /**
     * Removes an group policy from this usecase policy.
     * Does not do anything if this policy has no group policy for the given group id.
     * The modification is not persistent, it only modifies the policy object in the memory.  
     * @param groupId 
     */
    public void removeGroupPolicy(String groupId) {
        for (int i = 0; i < userOrGroupPolicies.size(); i++) {
            if (userOrGroupPolicies.get(i) instanceof GroupPolicy) {
                GroupPolicy gp = (GroupPolicy)userOrGroupPolicies.get(i);
                if (groupId.equals(gp.getId())) {
                    userOrGroupPolicies.remove(i);
                    return;
                }
            }
        }
        log.warn("No such group: " + groupId);
/* DEPRECATED
        for (int i = 0; i < gps.size(); i++) {
            GroupPolicy gp = (GroupPolicy)gps.elementAt(i);
            if (groupId.equals(gp.getId())) {
                gps.remove(i);
                return;
            }
        }
*/
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
     * Merge another UsecasePolicy with this UsecasePolicy
     * @param up UsecasePolicy to be merged with this UsecasePolicy
     */
    public void merge(UsecasePolicy up) {
        if (!getName().equals(up.getName())) {
            log.error("Usecase policies do not have the same names/IDs: " + getName() + " != " + up.getName());
            return;
        }

        // Merge identities
        IdentityPolicy[] upIdps = up.getIdentityPolicies();
        for (int i = 0; i < upIdps.length; i++) {
            //log.debug("IdentityPolicy (UsecasePolicy: " + up.getName() + "): " + upIdps[i].getIdentity().getUsername());
            boolean identityAlreadyExists = false;

            for (int k = 0; k < userOrGroupPolicies.size(); k++) {
                if (userOrGroupPolicies.get(k) instanceof IdentityPolicy) {
                    IdentityPolicy idp = (IdentityPolicy)userOrGroupPolicies.get(k);
                    if (upIdps[i].getIdentity().getUsername() != null && idp.getIdentity().getUsername() != null && idp.getIdentity().getUsername().equals(upIdps[i].getIdentity().getUsername())) {
                        identityAlreadyExists = true;
                        if (upIdps[i].getPermission() != idp.getPermission()) {
                            log.warn("Identity Policies '" + idp.getIdentity().getUsername() + "' of Usecase Policy '" + up.getName() + "' do not have the same permission!");
                        }
                        break;
                    }
                    // INFO: Check for WORLD
                    if (upIdps[i].getIdentity().getUsername() == null && idp.getIdentity().getUsername() == null) {
                        identityAlreadyExists = true;
                        if (upIdps[i].getPermission() != idp.getPermission()) {
                            log.warn("Identity Policies 'WORLD' of Usecase Policy '" + up.getName() + "' do not have the same permission!");
                        }
                        break;
                    }
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

            for (int k = 0; k < userOrGroupPolicies.size(); k++) {
                if (userOrGroupPolicies.get(k) instanceof GroupPolicy) {
                    GroupPolicy gp = (GroupPolicy)userOrGroupPolicies.get(k);
                    if (gp.getId().equals(upGps[i].getId())) {
                        groupAlreadyExists = true;
                        log.debug("Group policy already exists for group: " + gp.getId());
                        break;
                    }
                }
            }
/* DEPRECATED
            for (int k = 0; k < gps.size(); k++) {
                if (((GroupPolicy) gps.elementAt(k)).getId().equals(upGps[i].getId())) {
                    groupAlreadyExists = true;
                    break;
                }
            }
*/
            if (!groupAlreadyExists) {
                addGroupPolicy(upGps[i]);
            }
        }
    }

    /**
     * Get all user, group, etc. policies
     */
    public ItemPolicy[] getItemPolicies() {
        //log.debug("Number of item policies: " + userOrGroupPolicies.size());
        return (ItemPolicy[]) userOrGroupPolicies.toArray(new ItemPolicy[userOrGroupPolicies.size()]);
    }

    /**
     * @see java.lang.Object#equals(Object)
     */
    public boolean equals(Object object) {
        log.warn("DEBUG: Check whether these two usecase policies '" + getName() + "' are equal...");

        log.warn("TODO: What about world!");

        UsecasePolicy thatUsecasePolicy = (UsecasePolicy) object;

        IdentityPolicy[] ipsOfThis = getIdentityPolicies();
        for (int i = 0; i < ipsOfThis.length; i++) {
            Identity userID = ipsOfThis[i].getIdentity();
            if (thatUsecasePolicy.getIdentityPolicy(userID) == null) {
                log.warn("That usecase policy does not contain identity policy '" + userID + "' of this usecase policy!");
                return false;
            }
            if (thatUsecasePolicy.getIdentityPolicy(userID).getPermission() != getIdentityPolicy(userID).getPermission()) {
                log.warn("The identity policy '" + userID + "' of this and that usecase policy do not have the same permission!");
                return false;
            }
        }

        IdentityPolicy[] ipsOfThat = thatUsecasePolicy.getIdentityPolicies();
        for (int i = 0; i < ipsOfThat.length; i++) {
            Identity userID = ipsOfThat[i].getIdentity();
            if (getIdentityPolicy(userID) == null) {
                log.warn("This usecase policy does not contain identity policy '" + userID + "' of that usecase policy!");
                return false;
            }
            if (thatUsecasePolicy.getIdentityPolicy(userID).getPermission() != getIdentityPolicy(userID).getPermission()) {
                log.warn("The identity policy '" + userID + "' of this and that usecase policy do not have the same permission!");
                return false;
            }
        }

        GroupPolicy[] gpsOfThis = getGroupPolicies();
        for (int i = 0; i < gpsOfThis.length; i++) {
            String groupID = gpsOfThis[i].getId();
            if (thatUsecasePolicy.getGroupPolicy(groupID) == null) {
                log.warn("That usecase policy does not contain group policy '" + groupID + "' of this usecase policy!");
                return false;
            }
            if (thatUsecasePolicy.getGroupPolicy(groupID).getPermission() != getGroupPolicy(groupID).getPermission()) {
                log.warn("The group policy '" + groupID + "' of this and that usecase policy do not have the same permission!");
                return false;
            }
        }

        GroupPolicy[] gpsOfThat = thatUsecasePolicy.getGroupPolicies();
        for (int i = 0; i < gpsOfThat.length; i++) {
            String groupID = gpsOfThat[i].getId();
            if (getGroupPolicy(groupID) == null) {
                log.warn("This usecase policy does not contain group policy '" + groupID + "' of that usecase policy!");
                return false;
            }
            if (thatUsecasePolicy.getGroupPolicy(groupID).getPermission() != getGroupPolicy(groupID).getPermission()) {
                log.warn("The group policy '" + groupID + "' of this and that usecase policy do not have the same permission!");
                return false;
            }
        }

        return true;
    }
}
