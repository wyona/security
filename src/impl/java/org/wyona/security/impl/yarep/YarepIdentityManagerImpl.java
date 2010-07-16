package org.wyona.security.impl.yarep;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.ConfigurationException;
import org.apache.log4j.Logger;
import org.wyona.security.core.AuthenticationException;
import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.GroupManager;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.security.core.api.UserManager;
import org.wyona.yarep.core.Repository;

/**
 *
 */
public class YarepIdentityManagerImpl implements IdentityManager {
    protected static Logger log = Logger.getLogger(YarepIdentityManagerImpl.class);

    protected Repository identitiesRepository;
    protected UserManager userManager;
    protected GroupManager groupManager;

    //TODO: the field should be used somewhere?
    private static String CONFIG= "ac-identities-yarep.properties";

    /**
     * No initialization, subclasses should use configure()
     */
    protected YarepIdentityManagerImpl() {
    }
    
    /**
     *  Basic initialization
     *  @param identitiesRepository Peristent repository where users and groups are stored
     *  @param load Load users and groups into memory during initialization
     */
    public YarepIdentityManagerImpl(Repository identitiesRepository, boolean load) throws AccessManagementException {
        this.identitiesRepository = identitiesRepository;

/*
        boolean cacheEnabled = true;
        log.warn("Cache enabled!");
*/
        boolean cacheEnabled = false;
        log.warn("Cache disabled!");

        boolean resolveGroupsAtCreation = false;
        log.warn("Resolving of groups at user creation disabled!");

        userManager = new YarepUserManager(this, identitiesRepository, cacheEnabled, resolveGroupsAtCreation);
        groupManager = new YarepGroupManager(this, identitiesRepository, cacheEnabled);

        //userManager.getUsers(load);

        //((YarepGroupManager) groupManager).loadGroups();
    }
    
    /**
     *
     */
    protected void configure(Configuration config) throws ConfigurationException, AccessManagementException{
        log.warn("Configurable identity managers should override this method!");
    }
    
    /**
     * @deprecated
     */
    public boolean authenticate(String username, String password) throws AuthenticationException {
        try {
            return this.userManager.getUser(username).authenticate(password);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AuthenticationException(e);
        }
    }


    public GroupManager getGroupManager() {
        return this.groupManager;
    }


    public UserManager getUserManager() {
        return this.userManager;
    }
}
