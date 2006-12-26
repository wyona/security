package org.wyona.security.impl;

import java.util.Hashtable;

import org.wyona.commons.io.Path;
import org.wyona.security.core.AuthorizationException;
import org.wyona.security.core.api.Identity;
import org.wyona.security.core.api.PolicyManager;
import org.wyona.security.core.api.Role;
import org.wyona.yarep.core.NoSuchNodeException;
import org.wyona.yarep.core.Repository;
import org.wyona.yarep.core.RepositoryFactory;
import org.wyona.yarep.util.RepoPath;
import org.wyona.yarep.util.YarepUtil;

import org.apache.log4j.Category;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.DefaultConfigurationBuilder;

/**
 *
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
     *
     */
    public boolean authorize(Path path, Identity identity, Role role) throws AuthorizationException {
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
    private boolean authorize(Repository repo, Path path, Identity identity, Role role) throws Exception {
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

        try {
            org.wyona.yarep.core.Path yarepPath = new org.wyona.yarep.core.Path(getPolicyPath(path).toString());
            log.debug("Policy Yarep Path: " + yarepPath + ", Original Path: " + path + ", Repo: " + repo);
            Configuration config = configBuilder.build(repo.getInputStream(yarepPath));
            Configuration[] roles = config.getChildren("role");
            for (int i = 0; i < roles.length; i++) {
                String roleName = roles[i].getAttribute("id", null);
                if (roleName != null && roleName.equals(role.getName())) {
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
                }
            }
        } catch(NoSuchNodeException e) {
            log.info(e.getMessage());
        }

        Path parent = path.getParent();
        if (parent != null) {
            // Check policy of parent in order to inherit credentials ...
            log.debug("Check parent policy: " + parent + " ... (Current path: " + path + ")");
            return authorize(repo, new org.wyona.yarep.core.Path(parent.toString()), identity, role);
        } else {
            log.debug("Access denied: " + path);
            return false;
        }
    }

    /**
     *
     */
    public Path getPolicyPath(Path path) {
        // Remove trailing slash except for ROOT ...
        String p = path.toString();
        if (p.length() > 1 && p.charAt(p.length() - 1) == '/') {
            return new Path(p.substring(0, p.length() - 1) + ".policy");
        }
        return new Path(p + ".policy");
    }
}
