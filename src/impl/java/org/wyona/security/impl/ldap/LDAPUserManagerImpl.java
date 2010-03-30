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
    public boolean existsUser(String userName) throws AccessManagementException {
        log.error("TODO: LDAP Yarep Implementation not finished yet! Use Yarep-only implementation instead.");
        return new org.wyona.security.impl.yarep.YarepUserManager(identityManager, identitiesRepository).existsUser(userName);
    }

    /**
     * @see org.wyona.security.core.api.UserManager#removeUser(String)
     */
    public void removeUser(String userName) throws AccessManagementException {
        log.error("TODO: LDAP Yarep Implementation not finished yet! Use Yarep-only implementation instead.");
        new org.wyona.security.impl.yarep.YarepUserManager(identityManager, identitiesRepository).removeUser(userName);
    }

    /**
     * @see org.wyona.security.core.api.UserManager#createUser(String, String, String, String)
     */
    public User createUser(String id, String name, String email, String password) throws AccessManagementException {
        log.error("TODO: LDAP Yarep Implementation not finished yet! Use Yarep-only implementation instead.");
        return new org.wyona.security.impl.yarep.YarepUserManager(identityManager, identitiesRepository).createUser(id, name, email, password);
    }

    /**
     * @see org.wyona.security.core.api.UserManager#getUser(String)
     */
    public User getUser(String id) throws AccessManagementException {
        log.error("TODO: LDAP Yarep Implementation not finished yet! Use Yarep-only implementation instead.");
        return new org.wyona.security.impl.yarep.YarepUserManager(identityManager, identitiesRepository).getUser(id);
    }

    /**
     * @see org.wyona.security.core.api.UserManager#getUser(String, boolean)
     */
    public User getUser(String id, boolean refresh) throws AccessManagementException {
        log.error("TODO: LDAP Yarep Implementation not finished yet! Use Yarep-only implementation instead.");
        return new org.wyona.security.impl.yarep.YarepUserManager(identityManager, identitiesRepository).getUser(id, refresh);
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
            log.error("TODO: LDAP Yarep Implementation not finished yet! Use Yarep-only implementation instead.");
            return new org.wyona.security.impl.yarep.YarepUserManager(identityManager, identitiesRepository).getUsers(true);
        }
    }

    /**
     * @see org.wyona.security.core.api.UserManager#getUsers()
     */
    public User[] getUsers() throws AccessManagementException {
        log.warn("TODO: Make default value of load flag configurable");
        return getUsers(false);
    }
}
