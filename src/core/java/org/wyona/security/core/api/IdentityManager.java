package org.wyona.security.core.api;

/**
 *
 */
public interface IdentityManager {

    /**
     *
     */
    public boolean authenticate(String username, String password, String realmID);
}
