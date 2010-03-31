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

    /**
     * @see org.wyona.security.impl.ldap.LDAPClient#setProviderURL(String)
     */
    public void setProviderURL(String url) throws Exception {
        this.url = url;
    }

    /**
     * @see org.wyona.security.impl.ldap.LDAPClient#getAllUsernames()
     */
    public String[] getAllUsernames() throws Exception {
        // Create connection
        InitialLdapContext ldapContext = getInitialLdapContext();

        // Search
        //NamingEnumeration results = ldapContext.search(new CompositeName("ou=system"), "(cn=system*)", null); // TODO: Make filter configurable
        NamingEnumeration results = ldapContext.search(new CompositeName("ou=system"), "(objectClass=*)", null); // TODO: Make filter configurable
        //NamingEnumeration results = ldapContext.search(new CompositeName("ou=system"), "(objectClass=person)", null); // TODO: Make filter configurable

        // Analyze results
        java.util.List<String> users = new java.util.ArrayList<String>();
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
    private InitialLdapContext getInitialLdapContext() throws Exception {
        Properties ldapProps = new Properties();

        ldapProps.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory"); // TODO: Make LDAP context factory configurable
        if (url != null) {
            ldapProps.put(Context.PROVIDER_URL, url);
        } else {
            throw new Exception("No provider URL configured!");
        }
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
