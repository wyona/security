package org.wyona.security.core.api;

import org.wyona.security.core.AuthenticationException;
import org.wyona.yarep.core.Repository;

/**
 *
 */
public interface IdentityManager {

    /**
     *
     */
    public boolean authenticate(String username, String password) throws AuthenticationException;
    

}
