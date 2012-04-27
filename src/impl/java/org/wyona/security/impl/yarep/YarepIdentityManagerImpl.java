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
 * Identity manager implementation based on Yarep
 */
public class YarepIdentityManagerImpl implements IdentityManager {
    protected static Logger log = Logger.getLogger(YarepIdentityManagerImpl.class);

    protected Repository identitiesRepository;
    protected UserManager userManager;
    protected GroupManager groupManager;

    private String YAREP_IDENTITY_MANAGER_CONFIG_NS = "http://www.wyona.org/yarep/1.0.0";

    /**
     * No initialization, subclasses should do their own initialization
     */
    protected YarepIdentityManagerImpl() {
    }
    
    /**
     *  Basic initialization
     *  @param identitiesRepository Peristent repository where users and groups are stored
     *  @param load Load users and groups into memory during initialization
     */
    public YarepIdentityManagerImpl(Repository identitiesRepository, boolean load) throws AccessManagementException {
        init(identitiesRepository, load);
    }
    
    /**
     * Basic initialization of yarep based identity manager
     * @param configuration
     * @param resolver
     * @param load Load users and groups into memory during initialization
     */
    public YarepIdentityManagerImpl(org.w3c.dom.Document configuration, javax.xml.transform.URIResolver resolver, boolean load) throws AccessManagementException {
        try {
            String targetEnv = configuration.getDocumentElement().getAttribute("target-environment");

            String repoFileName = org.wyona.commons.xml.XMLHelper.getChildElements(configuration.getDocumentElement(), "repository-config", YAREP_IDENTITY_MANAGER_CONFIG_NS)[0].getTextContent(); // INFO: Get from DOM document configuration <identity-manager-config xmlns="http://www.wyona.org/security/1.0"><yarep:repository-config xmlns:yarep="http://www.wyona.org/yarep/1.0.0">config/ac-identities-repository.xml</yarep:repository-config></identity-manager-config>

            log.warn("Get target environment and repository configuration from identity manager config: " + targetEnv + ", " + repoFileName);

            java.io.File repoConfigFile = new java.io.File(resolver.resolve(repoFileName, null).getSystemId());

            Repository repo = new org.wyona.yarep.core.RepositoryFactory().newRepository("ID_DOES_NOT_MATTER", repoConfigFile); // INFO: The repository ID does not matter as long as the repository factory is not a singleton!

            String groupImplClazz = getGroupImplClazz(configuration);
            if (groupImplClazz != null) {
                log.warn("DEBUG: Group implementation class configured: " + groupImplClazz);
            }
            init(repo, load);
        } catch(Exception e) {
            log.error(e, e);
            throw new AccessManagementException(e);
        }
    }

    /**
     *  Basic initialization
     *  @param identitiesRepository Peristent repository where users and groups are stored
     *  @param load Load users and groups into memory during initialization
     */
    private void init(Repository identitiesRepository, boolean load) throws AccessManagementException {
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
     * @deprecated
     * Configure identity manager
     * @param configuration XML containing identity manager configuration
     */
/* WARN: This method is not used anywhere inside the security library, but because third party implementations might override this method (@Override) we might better just set it to deprecated in order to stay backwards compatible
    protected void configure(Configuration config) throws ConfigurationException, AccessManagementException{
        log.warn("Configurable identity managers should override this method!");
    }
*/
    
    /**
     * @deprecated Use User.authenticate(String) instead
     */
    public boolean authenticate(String username, String password) throws AuthenticationException {
        try {
            return this.userManager.getUser(username).authenticate(password);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AuthenticationException(e);
        }
    }

    /**
     *
     */
    public GroupManager getGroupManager() {
        return this.groupManager;
    }

    /**
     *
     */
    public UserManager getUserManager() {
        return this.userManager;
    }

    /**
     * Try to get group implementation class from identity manager configuration, e.g. <identity-manager-config xmlns="http://www.wyona.org/security/1.0"><yarep:repository-config xmlns:yarep="http://www.wyona.org/yarep/1.0.0">config/ac-identities-repository.xml</yarep:repository-config><yarep:group-implementation class="org.wyona.security.impl.yarep.YarepGroupImplV2"/></identity-manager-config>
     * @param configuration Identity manager configuration
     */
    private String getGroupImplClazz(org.w3c.dom.Document configuration) throws Exception {
        org.w3c.dom.Element[] groupImplElements = org.wyona.commons.xml.XMLHelper.getChildElements(configuration.getDocumentElement(), "group-implementation", YAREP_IDENTITY_MANAGER_CONFIG_NS);

        if (groupImplElements != null && groupImplElements.length == 1) {
            return groupImplElements[0].getAttribute("class");
        }
        log.warn("No group implementation class configured.");
        return null;
    }
}
