package org.wyona.security.core.api;

import org.wyona.commons.io.Path;
import org.wyona.security.core.AuthorizationException;
import org.wyona.yarep.core.Repository;

/**
 *
 */
public interface PolicyManager {

    /**
     * @deprecated
     */
    public boolean authorize(Path path, Identity identity, Role role) throws AuthorizationException;
    
    /**
     * @deprecated
     */
    public boolean authorize(String path, Identity identity, Role role) throws AuthorizationException;
    
    /**
     *
     */
    public boolean authorize(String path, Identity identity, Usecase usecase) throws AuthorizationException;
   
    /**
     * Get policies repository of realm
     */
     public Repository getPoliciesRepository();
}
