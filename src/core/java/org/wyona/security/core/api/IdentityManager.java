package org.wyona.security.core.api;

import org.wyona.security.core.AuthenticationException;

/**
 *
 */
public interface IdentityManager {

    /**
     * @deprecated
     * please use getUserManager().getUser(username).authenticate(password) instead.
     */
    public boolean authenticate(String username, String password) throws AuthenticationException;
    
    /**
     * Gets the user manager which belongs to this IdentityManager.
     * @return user manager
     */
    public UserManager getUserManager();
    
    /**
     * Gets the group manager which belongs to this IdentityManager.
     * @return group manager
     */
    public GroupManager getGroupManager();
}
