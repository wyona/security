package org.wyona.security.impl.ldap;

/**
 *
 */
public interface LDAPClient {

    /**
     * Set URL of LDAP server
     * @param url URL of LDAP server, e.g. ldap://127.0.0.1:389
     */
    public void setProviderURL(String url) throws Exception;

    /**
     * Set security authentication mechanism
     * @param am Security authentication mechanism, e.g. simple (also see http://java.sun.com/products/jndi/tutorial/ldap/security/ldap.html)
     */
    public void setAuthenticationMechanism(String am) throws Exception;

    /**
     * Set security protocol
     * @param protocol Security protocol, e.g. ssl
     */
    public void setSecurityProtocol(String protocol) throws Exception;

    /**
     * Set credentials
     * @param userDN The full user DN (distinguished name, e.g "uid=schroedinger,dc=example,dc=com"
     * @param password Password associated with username
     */
    public void setCredentials(String userDB, String password) throws Exception;

    /**
     * Get all usernames
     */
    public String[] getAllUsernames() throws Exception;

    /**
     * Get all usernames
     * @param contextName Name of context, e.g. "uid=tesla,dc=example,dc=com"
     * @param matchingAttributes The attributes to search for, e.g. "(objectClass=*)"
     */
    public String[] getAllUsernames(String contextName, String matchingAttributes) throws Exception;
}
