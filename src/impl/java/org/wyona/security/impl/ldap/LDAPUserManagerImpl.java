package org.wyona.security.impl.ldap;

import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.security.core.api.User;
import org.wyona.security.core.api.UserManager;

import org.wyona.yarep.core.Repository;

import org.apache.log4j.Logger;

/**
 * LDAP user manager implementation
 */
public class LDAPUserManagerImpl implements UserManager {

    private static Logger log = Logger.getLogger(LDAPUserManagerImpl.class);

    private Repository identitiesRepository;
    private IdentityManager identityManager;
    private LDAPClient ldapClient;

    /**
     * Constructor
     * @param identityManager Identity manager from which this user manager implementation is called
     * @param identitiesRepository Repository containing "cached" LDAP users
     */
    public LDAPUserManagerImpl(IdentityManager identityManager, Repository identitiesRepository, LDAPClient ldapClient) {
        this.identityManager = identityManager;
        this.identitiesRepository = identitiesRepository;
        this.ldapClient = ldapClient;
    }

    /**
     * @see org.wyona.security.core.api.UserManager#existsUser(String)
     */
    public boolean existsUser(String userName) {
        log.error("TODO: Implementation not finished yet!");
        return false;
    }

    /**
     * @see org.wyona.security.core.api.UserManager#removeUser(String)
     */
    public void removeUser(String userName) {
        log.error("TODO: Implementation not finished yet!");
    }

    /**
     * @see org.wyona.security.core.api.UserManager#createUser(String, String, String, String)
     */
    public User createUser(String id, String name, String email, String password) {
        log.error("TODO: Implementation not finished yet!");
        return null;
    }

    /**
     * @see org.wyona.security.core.api.UserManager#getUser(String)
     */
    public User getUser(String id) {
        log.error("TODO: Implementation not finished yet!");
        return null;
    }

    /**
     * @see org.wyona.security.core.api.UserManager#getUser(String, boolean)
     */
    public User getUser(String id, boolean refresh) {
        log.error("TODO: Implementation not finished yet!");
        return null;
    }

    /**
     * @see org.wyona.security.core.api.UserManager#getUsers(boolean)
     */
    public User[] getUsers(boolean refresh) throws AccessManagementException {
        if (refresh) {
            log.error("TODO: LDAP Implementation not finished yet!");
            try {
                String[] usernames = ldapClient.getAllUsernames();
                java.util.List<User> users = new java.util.ArrayList<User>();
                for (int i = 0; i < usernames.length; i++) {
                    log.warn("DEBUG: Username: " + usernames[i]);
                    // TODO: ...
                    //users.add(new LDAPYarepUserImpl()); 
                }
                return users.toArray(new User[users.size()]);
            } catch(Exception e) {
                log.error(e, e);
                throw new AccessManagementException(e.getMessage(), e);
            }
        } else {
            log.error("TODO: Yarep Implementation not finished yet!");
            return new org.wyona.security.impl.yarep.YarepUserManager(identityManager, identitiesRepository).getUsers(true);
        }
    }

    /**
     * @see org.wyona.security.core.api.UserManager#getUsers()
     */
    public User[] getUsers() {
        log.error("TODO: Implementation not finished yet!");
        return null;
    }
}
