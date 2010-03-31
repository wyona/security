package org.wyona.security.impl.ldap;

/**
 *
 */
public interface LDAPClient {

    /**
     * Set URL of LDAP server, e.g. ldap://127.0.0.1:389
     */
    public void setProviderURL(String url) throws Exception;

    /**
     * Get all usernames
     */
    public String[] getAllUsernames() throws Exception;
}
