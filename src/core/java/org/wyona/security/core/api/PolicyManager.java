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
     *
     */
    public boolean authorize(Policy policy, Identity identity, Usecase usecase) throws AuthorizationException;
   
    /**
     * Get policies repository
     */
     public Repository getPoliciesRepository();

    /**
     * @param path Path of content, e.g. /hello/world.html
     * @param aggregate Boolean which specifies if implementation shall return an aggregated policy, e.g. an aggregation of the policies for /, /hello/ and /hello/world.html
     * @return Policy which is associated with content path
     */
    public Policy getPolicy(String path, boolean aggregate) throws AuthorizationException;
}
