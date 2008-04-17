package org.wyona.security.impl;

import java.util.Hashtable;

import org.wyona.commons.io.Path;
import org.wyona.commons.io.PathUtil;
import org.wyona.security.core.AuthorizationException;
import org.wyona.security.core.GroupPolicy;
import org.wyona.security.core.IdentityPolicy;
import org.wyona.security.core.UsecasePolicy;
import org.wyona.security.core.api.Identity;
import org.wyona.security.core.api.Policy;
import org.wyona.security.core.api.PolicyManager;
import org.wyona.security.core.api.Role;
import org.wyona.security.core.api.Usecase;
import org.wyona.yarep.core.NoSuchNodeException;
import org.wyona.yarep.core.Repository;
import org.wyona.yarep.core.RepositoryException;
import org.wyona.yarep.core.RepositoryFactory;
import org.wyona.yarep.util.RepoPath;
import org.wyona.yarep.util.YarepUtil;

import org.apache.log4j.Category;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.DefaultConfigurationBuilder;

/**
 * @deprecated
 */
public class PolicyManagerImpl implements PolicyManager {

    private static Category log = Category.getInstance(PolicyManagerImpl.class);

    private Repository policiesRepository;
    private DefaultConfigurationBuilder configBuilder;

    /**
     *
     */
    public PolicyManagerImpl(Repository policiesRepository) {
        this.policiesRepository = policiesRepository;
        configBuilder = new DefaultConfigurationBuilder();
    }
    
    /**
     * Get policies repository
     */
     public Repository getPoliciesRepository() {
           return policiesRepository;
     }
     
    /**
     * @deprecated
     */
    public boolean authorize(Path path, Identity identity, Role role) throws AuthorizationException {
        return authorize(path.toString(), identity, role);
    }
     
    /**
     *
     */
    public boolean authorize(Policy policy, Identity identity, Usecase usecase) throws AuthorizationException {
        log.error("Not implemented yet!");
        return false;
    }

    /**
     *
     */
    public boolean authorize(String path, Identity identity, Usecase usecase) throws AuthorizationException {
        Role role = new Role(usecase.getName());
        return authorize(path, identity, role);
    }
   
    /**
     * @deprecated
     */
    public boolean authorize(String path, Identity identity, Role role) throws AuthorizationException {
        if(path == null || identity == null || role == null) {
            log.error("Path or identity or role is null! [" + path + ", " + identity + ", " + role + "]");
            throw new AuthorizationException("Path or identity or role is null! [" + path + ", " + identity + ", " + role + "]");
        }

        try {
            return authorize(policiesRepository, path, identity, role);
        } catch(Exception e) {
            log.error(e.getMessage(), e);
            throw new AuthorizationException("Error authorizing " + policiesRepository.getID() + 
                    ", " + path + ", " + identity + ", " + role, e);
        }
    }

    /**
     *
     */
    private boolean authorize(Repository repo, String path, Identity identity, Role role) throws Exception {
        if(repo == null) {
            log.error("Repo is null!");
            throw new Exception("Repo is null!");
        } else if(path == null) {
            log.error("Path is null!");
            throw new Exception("Path is null!");
        } else if(identity == null) {
            log.error("Identity is null!");
            throw new Exception("Identity is null!");
        } else if(role == null) {
            log.error("Role is null!");
            throw new Exception("Role is null!");
        }

        String yarepPath = getPolicyPath(path); 
        log.debug("Policy Yarep Path: " + yarepPath + ", Original Path: " + path + ", Repo: " + repo);
        if (repo.existsNode(yarepPath)) {
            try {
                Configuration config = configBuilder.build(repo.getNode(yarepPath).getInputStream());
                boolean useInheritedPolicies = config.getAttributeAsBoolean("use-inherited-policies", true);
            Configuration[] roles = config.getChildren("role");
            for (int i = 0; i < roles.length; i++) {
                String roleName = roles[i].getAttribute("id", null);
                if (roleName != null && roleName.equals(role.getName())) {
                    boolean useInheritedRolePolicies = roles[i].getAttributeAsBoolean("use-inherited-policies", true);
                    Configuration[] accreditableObjects = roles[i].getChildren();

                    boolean worldCredentialExists = false;
                    boolean worldIsNotAuthorized = true;
                    for (int k = 0; k < accreditableObjects.length; k++) {
                        String aObjectName = accreditableObjects[k].getName();
                        log.debug("Accreditable Object Name: " + aObjectName);

                        if (aObjectName.equals("world")) {
                            worldCredentialExists = true;
                            String permission = accreditableObjects[k].getAttribute("permission", null);
                            if (permission.equals("true")) {
                                log.debug("Access granted: " + path);
                                worldIsNotAuthorized = false;
                                return true;
                            } else {
                                worldIsNotAuthorized = true;
                            }
                        } else if (aObjectName.equals("group")) {
                            if (identity.getGroupnames() != null) {
                                String groupName = accreditableObjects[k].getAttribute("id", null);
                                String[] groupnames = identity.getGroupnames();
                                if (groupnames != null) {
                                    for (int j = 0; j < groupnames.length; j++) {
                                        if (groupName.equals(groupnames[j])) {
                                            String permission = accreditableObjects[k].getAttribute("permission", null);
                                            if (permission.equals("true")) {
                                                log.debug("Access granted: Path = " + path + ", Group = " + groupName);
                                                return true;
                                            } else {
                                                log.debug("Access denied: Path = " + path + ", Group = " + groupName);
                                                return false;
                                            }
                                        }
                                    }
                                }
                            }
                        } else if (aObjectName.equals("user")) {
                            if (identity.getUsername() != null) {
                                String userName = accreditableObjects[k].getAttribute("id", null);
                                if (userName.equals(identity.getUsername())) {
                                    String permission = accreditableObjects[k].getAttribute("permission", null);
                                    if (permission.equals("true")) {
                                        log.debug("Access granted: Path = " + path + ", User = " + userName);
                                        return true;
                                    } else {
                                        log.debug("Access denied: Path = " + path + ", User = " + userName);
                                        return false;
                                    }
                                }
                            }
                        } else if (aObjectName.equals("iprange")) {
                            log.warn("Credential IP Range not implemented yet!");
                            //return false;
                        } else {
                            log.warn("No such accreditable object implemented: " + aObjectName);
                            //return false;
                        }
                    }
                    if (worldCredentialExists && worldIsNotAuthorized) {
                       log.debug("Access for world denied: " + path);
                       return false;
                    }
                    if (!useInheritedRolePolicies){
                        log.debug("Policy inheritance disabled for role:" + roleName + ". Access denied: "+ path);
                        return false;
                    }
                }
            }
                if (!useInheritedPolicies) {
                    log.debug("Policy inheritance disabled. Access denied: "+ path);
                    return false;
                }
            } catch(NoSuchNodeException e) {
                log.error(e.getMessage(), e);
            }
        } else {
            if (yarepPath.equals("/.policy")) {
                log.warn("No such node: " + yarepPath + " (" + repo + ")");
            } else {
                if (log.isDebugEnabled()) log.debug("No such node: " + yarepPath + " (Fallback to parent policy ...)");
            }
        }

        String parent = PathUtil.getParent(path);
        if (parent != null) {
            // Check policy of parent in order to inherit credentials ...
            log.debug("Check parent policy: " + parent + " ... (Current path: " + path + ")");
            return authorize(repo, parent, identity, role);
        } else {
            log.warn("Trying to get parent of " + path + " (" + repo + ") failed. Access denied.");
            return false;
        }
    }

    /**
     * Append '.policy' to path as suffix
     */
    private String getPolicyPath(String path) {
        // Remove trailing slash except for ROOT ...
        if (path.length() > 1 && path.charAt(path.length() - 1) == '/') {
            return path.substring(0, path.length() - 1) + ".policy";
        }
        return path + ".policy";
    }

    /**
     *
     */
    public Policy getPolicy(String path, boolean aggregate) throws AuthorizationException {
        try {
            if (aggregate) {
                return org.wyona.security.impl.util.PolicyAggregator.aggregatePolicy(path, this);
            } else {
                if (getPoliciesRepository().existsNode(getPolicyPath(path))) {
                    return new PolicyImplVersion1(getPoliciesRepository().getNode(getPolicyPath(path)).getInputStream());
                } else {
                    if (!path.equals("/")) {
                        log.warn("No policy found for '" + path + "' (Policies Repository: " + getPoliciesRepository().getName() + "). Check for parent '" + PathUtil.getParent(path) + "'.");
                        return null;
                        //return getPolicy(PathUtil.getParent(path), false);
                    } else {
                        log.warn("No policies found at all, not even a root policy!");
                        return null;
                    }
                }
            }
        } catch(Exception e) {
            log.error(e, e);
            throw new AuthorizationException(e.getMessage());
        }
    }

    /**
     * @see
     */
    public void setPolicy(String path, Policy policy) throws AuthorizationException {
        //log.warn("Not implemented yet!");
        //throw new java.lang.UnsupportedOperationException("Setting policy by this policy manager '" + this.getClass().getName() + "' not implemented yet!");

        StringBuffer sb = new StringBuffer("<?xml version=\"1.0\"?>");
        sb.append("\n\n<policy xmlns=\"http://www.wyona.org/security/1.0\" use-inherited-policies=\"" + policy.useInheritedPolicies() + "\">");

        UsecasePolicy[] up = policy.getUsecasePolicies();
        if (up != null && up.length > 0) {
            for (int i = 0; i < up.length; i++) {
                String useInheritedPoliciesStr = "";
                if (!up[i].useInheritedPolicies()) {
                    useInheritedPoliciesStr = " use-inherited-policies=\"false\"";
                }
                sb.append("\n\n<role id=\"" + up[i].getName() + "\"" + useInheritedPoliciesStr + ">");
                sb.append(getIdentitiesGroupsAsXML(up[i]));
                sb.append("\n</role>");

/*
                if (up[i].getName().equals("r")) {
                    sb.append("\n\n<role id=\"" + "r" + "\"" + useInheritedPoliciesStr + ">");
                    sb.append(getIdentitiesGroupsAsXML(up[i]));
                    sb.append("\n</role>");
                } else if (up[i].getName().equals("w")) {
                    sb.append("\n\n<role id=\"" + "w" + "\"" + useInheritedPoliciesStr + ">");
                    sb.append(getIdentitiesGroupsAsXML(up[i]));
                    sb.append("\n</role>");
                } else {
                    log.warn("No such usecase supported: " + up[i].getName());
                }
*/
            }
        } else {
            log.warn("No usecases for policy associated with " + path);
        }
        sb.append("\n</policy>");

        //log.debug("Policy: " + sb);

        Repository repo = getPoliciesRepository();
        String policyPath = getPolicyPath(path);
        try {
            if (repo.existsNode(policyPath)) {
                log.warn("Existing policy will be overwritten: " + policyPath);
            } else {
                org.wyona.yarep.util.YarepUtil.addNodes(repo, policyPath, org.wyona.yarep.core.NodeType.RESOURCE);
                log.warn("New policy node has been created: " + policyPath);
            }
            org.wyona.yarep.core.Node policyNode = getPoliciesRepository().getNode(policyPath);
            java.io.Writer writer = new java.io.OutputStreamWriter(policyNode.getOutputStream(), "UTF-8");
            writer.write(sb.toString());
            writer.close();
            log.warn("Policy has been overwritten: " + policyPath);
        } catch (Exception e) {
            log.error(e, e);
            throw new AuthorizationException(e.getMessage());
        }
    }

    /**
     *
     */
    private StringBuffer getIdentitiesGroupsAsXML(UsecasePolicy up) {
        StringBuffer sb = new StringBuffer();

        IdentityPolicy[] idps = up.getIdentityPolicies();
        for (int k = 0; k < idps.length; k++) {
            sb.append("\n  <user id=\"" + idps[k].getIdentity().getUsername() + "\" permission=\"" + idps[k].getPermission() + "\"/>");
        }

        GroupPolicy[] gps = up.getGroupPolicies();
        for (int k = 0; k < gps.length; k++) {
            sb.append("\n  <group id=\"" + gps[k].getId() + "\" permission=\"" + gps[k].getPermission() + "\"/>");
        }

        return sb;
    }

    /**
     * @see
     */
    public String[] getUsecases() {
        log.warn("TODO: Implementation not finished yet! Read from configuration instead hardcoded!");
        String[] usecases = {"view", "open", "write", "toolbar", "create", "delete"};
        return usecases;
    }

    /**
     * @see
     */
    public String getUsecaseLabel(String usecaseId, String language) {
        log.warn("TODO: Implementation not finished yet! Read from configuration instead hardcoded!");
        if (language.equals("de")) {
            if (usecaseId.equals("view")) {
                return "Anschauen/Lesen";
            } else if (usecaseId.equals("open")) {
                return "Open content for editing";
            } else if (usecaseId.equals("toolbar")) {
                return "Toolbar";
            } else {
                return "No label for \"" + usecaseId + "\"";
            }
        } else {
            if (usecaseId.equals("view")) {
                return "View/Read";
            } else if (usecaseId.equals("open")) {
                return "Open content for editing";
            } else if (usecaseId.equals("write")) {
                return "Write/Save";
            } else if (usecaseId.equals("toolbar")) {
                return "Toolbar";
            } else {
                return "No label for \"" + usecaseId + "\"";
            }
        }
    }

    public Policy createEmptyPolicy() throws AuthorizationException {
        try {
            return new PolicyImplVersion1();
        } catch (Exception e) {
            throw new AuthorizationException(e.getMessage(), e);
        }
    }
    
    public void removePolicy(String path) throws AuthorizationException {
        Repository repo = getPoliciesRepository();
        String policyPath = getPolicyPath(path);
        try {
            if (repo.existsNode(policyPath)) {
                repo.getNode(policyPath).delete();
            }
        } catch (RepositoryException e) {
            throw new AuthorizationException("could not remove policy for path: " + path + 
                    ": " + e.getMessage(), e);
        }
    }
}
