package org.wyona.security.impl;

import java.util.Hashtable;

import org.wyona.security.core.AuthenticationException;
import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.GroupManager;
import org.wyona.security.core.api.Identity;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.security.core.api.UserManager;
import org.wyona.security.impl.yarep.YarepGroupManager;
import org.wyona.security.impl.yarep.YarepUserManager;
import org.wyona.yarep.core.Path;
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
public class IdentityManagerImpl implements IdentityManager {

    private static Category log = Category.getInstance(IdentityManagerImpl.class);

    private Repository identitiesRepository;
    private DefaultConfigurationBuilder configBuilder;
    private UserManager userManager;
    private GroupManager groupManager;

    private static String CONFIG= "ac-identities-yarep.properties";

    /**
     *
     */
    public IdentityManagerImpl(Repository identitiesRepository) {
        this.identitiesRepository = identitiesRepository;
        configBuilder = new DefaultConfigurationBuilder(true);
        try {
            // TODO: make implementation configurable:
            userManager = new YarepUserManager(this, this.identitiesRepository);
            groupManager = new YarepGroupManager(this, this.identitiesRepository);
        } catch (AccessManagementException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException(e.getMessage(), e); // FIXME
        }
    }

    
    /**
     *
     */
    public boolean authenticate(String username, String password) throws AuthenticationException {
        if(username == null || password == null) {
            log.warn("Username or password is null!");
            return false;
        }

        /*if (repoID != null) {
            log.debug("Repository ID: " + repoID);
            if (repoFactory != null) {
                repo = repoFactory.newRepository(realmID);
            } else {
                log.error("Repository Factory is null! Check configuration: " + CONFIG);
            }
        } else {
            if (repoFactory != null) {
                repo = repoFactory.firstRepository();
            } else {
                log.error("Repository Factory is null! Check configuration: " + CONFIG);
            }
            log.debug("Realm ID is null and hence first repository will be used!");
        }*/
        log.debug("Repository: " + identitiesRepository);

        try {
            Configuration config = configBuilder.build(identitiesRepository.getInputStream(new Path("/" + username + ".iml")));
            
            String idVersion = config.getChild("password").getNamespace();
            if (idVersion.equals("http://www.wyona.org/security/1.0")) {
                Configuration passwdConfig = config.getChild("password");
                if (passwdConfig.getValue().equals(Password.getMD5(password))) return true;
            } else if (idVersion.equals("http://www.wyona.org/security/1.1")) {
                Configuration passwdConfig = config.getChild("password");
                String salt = config.getChild("salt").getValue();
                if(passwdConfig.getValue().equals(Password.getMD5(password,salt))) return true;
            } else {
                log.error("No such version implemented: " + idVersion);
                throw new AuthenticationException("Error authenticating " + identitiesRepository.getID() + ", " + username + ". No such version implemented: " + idVersion);
            }
        } catch(Exception e) {
            log.error(e.getMessage(), e);
            throw new AuthenticationException("Error authenticating " + identitiesRepository.getID() + ", " + username, e);
        }

        return false;
    }


    public GroupManager getGroupManager() {
        return this.groupManager;
    }


    public UserManager getUserManager() {
        return this.userManager;
    }
}
