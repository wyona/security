package org.wyona.security.impl.ldap;

import org.apache.log4j.Logger;

import java.util.Properties;
import javax.naming.CompositeName;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;

/**
 * LDAP client implementation
 */
public class LDAPClientImplV2 implements LDAPClient {

    private static Logger log = Logger.getLogger(LDAPClientImplV2.class);

    private String url;
    private String authenticationMechanism;
    private String securityProtocol;

    private String userDN;
    private String password;

    /**
     * @see org.wyona.security.impl.ldap.LDAPClient#setProviderURL(String)
     */
    public void setProviderURL(String url) throws Exception {
        this.url = url;
    }

    /**
     * @see org.wyona.security.impl.ldap.LDAPClient#setAuthenticationMechanism(String)
     */
    public void setAuthenticationMechanism(String am) throws Exception {
        this.authenticationMechanism = am;
    }

    /**
     * @see org.wyona.security.impl.ldap.LDAPClient#setSecurityProtocol(String)
     */
    public void setSecurityProtocol(String p) throws Exception {
        this.securityProtocol = p;
    }

    /**
     * @see org.wyona.security.impl.ldap.LDAPClient#setCredentials(String, String)
     */
    public void setCredentials(String userDN, String password) {
        this.userDN = userDN;
        this.password = password;
    }

    /**
     * @see org.wyona.security.impl.ldap.LDAPClient#getAllUsernames()
     */
    public String[] getAllUsernames() throws Exception {
        return getAllUsernames("ou=system", "(objectClass=*)");
        //return getAllUsernames("ou=system", "(cn=system*)");
        //return getAllUsernames("ou=system", "(objectClass=person)");
    }

    /**
     * @see org.wyona.security.impl.ldap.LDAPClient#getAllUsernames(String, String)
     */
    public String[] getAllUsernames(String contextName, String matchingAttributes) throws Exception {
        User[] users = getAllUsers(contextName, matchingAttributes);

        java.util.List<String> userNames = new java.util.ArrayList<String>();
        for (int i = 0; i < users.length; i++) {
            userNames.add(users[i].getUID());
        }

        return userNames.toArray(new String[userNames.size()]);
    }

    /**
     * Get all users
     */
    public User[] getAllUsers(String contextName, String matchingAttributes) throws Exception {
        // Create connection
        InitialLdapContext ldapContext = getInitialLdapContext();

        // Search
        NamingEnumeration results = ldapContext.search(new CompositeName(contextName), matchingAttributes, null);

        // Analyze results
        java.util.List<User> users = new java.util.ArrayList<User>();
        if (!results.hasMore()) {
            log.warn("No users found!");
        }
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
                        User user = new User(userId);
                        users.add(user);

                        Attribute mailAttribute = result.getAttributes().get("mail");
                        if (mailAttribute != null) {
                            NamingEnumeration mailValues = mailAttribute.getAll();
                            while(mailValues.hasMore()) {
                                String email = mailValues.next().toString();
                                log.warn("DEBUG: Email of user '" + userId + "': " + email);
                                user.setEmail(email);
                            }
                        } else {
                            log.warn("Search result has no 'mail' attribute: " + result);
                        }
                    }
                } else {
                    log.warn("Search result has no 'uid' attribute: " + result);
                }
            } else {
                log.warn("Search result has not attributes: " + result);
            }
        }
        ldapContext.close();
        return users.toArray(new User[users.size()]);
    }

    /**
     * Get initial LDAP context
     */
    private InitialLdapContext getInitialLdapContext() throws Exception {
        Properties ldapProps = new Properties();

        ldapProps.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        if (url != null) {
            ldapProps.put(Context.PROVIDER_URL, url);
        } else {
            throw new Exception("No provider URL configured!");
        }
        if  (authenticationMechanism != null) {
            ldapProps.put(Context.SECURITY_AUTHENTICATION, authenticationMechanism);

            // INFO: See https://docs.oracle.com/javase/jndi/tutorial/ldap/security/ldap.html
            if (userDN != null) {
                log.info("Set credentials to authenticate ...");
                ldapProps.setProperty(Context.SECURITY_PRINCIPAL, userDN);
                ldapProps.put(Context.SECURITY_CREDENTIALS, password);
            }
        } else {
            throw new Exception("No security authentication mechanism configured!");
        }

        // INFO: https://docs.oracle.com/javase/jndi/tutorial/ldap/security/ssl.html Either set SECURITY_PROTOCOL to 'ssl' or use ldaps URL
        if (securityProtocol != null) {
            ldapProps.put(Context.SECURITY_PROTOCOL, securityProtocol);
        } else {
            log.info("No security protocol set.");
        }

        // INFO: Connect anonymously!

        return new InitialLdapContext(ldapProps, null);
    }
}
