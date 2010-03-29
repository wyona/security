package org.wyona.security.impl.ldap;

import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.security.core.api.User;
import org.wyona.security.core.api.UserManager;

import org.wyona.yarep.core.Repository;

import org.apache.log4j.Logger;

import java.util.Properties;
import javax.naming.CompositeName;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;

/**
 * LDAP user manager implementation
 */
public class LDAPUserManagerImpl implements UserManager {

    private static Logger log = Logger.getLogger(LDAPUserManagerImpl.class);

    private Repository identitiesRepository;
    private IdentityManager identityManager;

    /**
     * Constructor
     * @param identityManager Identity manager from which this user manager implementation is called
     * @param identitiesRepository Repository containing "cached" LDAP users
     */
    public LDAPUserManagerImpl(IdentityManager identityManager, Repository identitiesRepository) {
        this.identityManager = identityManager;
        this.identitiesRepository = identitiesRepository;
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
                String[] usernames = getAllUsernamesFromLDAP();
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

    /**
     * Get all usernames from LDAP
     */
    private static String[] getAllUsernamesFromLDAP() throws Exception {
        // Create connection
        InitialLdapContext ldapContext = getInitialLdapContext();

        // Search
        NamingEnumeration results = ldapContext.search(new CompositeName("cn=eld,ou=Systems,dc=naz,dc=ch"), "(objectClass=accessRole)", null); // TODO: Make filter configurable

        // Analyze results
        java.util.List<String> users = new java.util.ArrayList<String>();
        while(results.hasMore()) {
            //log.warn("DEBUG: Result:");
            SearchResult result = (SearchResult) results.next();
            if (result.getAttributes().size() > 0) {
                Attribute uidAttribute = result.getAttributes().get("uid");
                if (uidAttribute != null) {
                    NamingEnumeration values = uidAttribute.getAll();
                    while(values.hasMore()) {
                        String userId = values.next().toString();
                        //log.warn("DEBUG: Value: " + userId);
                        users.add(userId);
                    }
                } else {
                    log.warn("Search result has no 'uid' attribute: " + result);
                }
            } else {
                log.warn("Search result has not attributes: " + result);
            }
        }
        ldapContext.close();
        return users.toArray(new String[users.size()]);
    }

    /**
     * Get initial LDAP context
     */
    private static InitialLdapContext getInitialLdapContext() throws Exception {
        Properties ldapProps = new Properties();

        ldapProps.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory"); // TODO: Make LDAP context factory configurable
        ldapProps.put(Context.PROVIDER_URL, "ldap://192.168.200.109:389"); // TODO: Make URL configurable
        ldapProps.put(Context.SECURITY_AUTHENTICATION, "simple"); // TODO: Make Security Authentication configurable

        String securityProtocol = null;
        //String securityProtocol = "ssl";
        if (securityProtocol != null) {
            ldapProps.put(Context.SECURITY_PROTOCOL, securityProtocol); // TODO: Make Security Protocol configurable
        }

        // INFO: Connect anonymously!

        return new InitialLdapContext(ldapProps, null);
    }
}
