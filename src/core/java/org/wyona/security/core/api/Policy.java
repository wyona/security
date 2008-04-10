package org.wyona.security.core.api;

import org.wyona.security.core.UsecasePolicy;

/**
 * A policy interface.
 */
public interface Policy {
    /**
     * Gets the usecase policy for the given usecase name or null if there is
     * no such usecase policy.
     * @param name
     * @return usecase policy or null
     * @throws AccessManagementException
     */
    public UsecasePolicy getUsecasePolicy(String name) throws AccessManagementException;
    
    /**
     * Gets the usecases/actions of policies.
     *
     * @return usecases declared within this policy
     */
    public UsecasePolicy[] getUsecasePolicies();

    /**
     * Adds a usecase to this policy. TBD: What if such a usecase already exists?
     *
     * @param usecase Usecase
     * @throws AccessManagementException
     */
    public void addUsecasePolicy(UsecasePolicy up) throws AccessManagementException;

    /**
     * Removes a usecase policy from this policy.
     * Does not do anything if this policy has no usecase policy with the given name.
     * The modification is not persistent, it only modifies the policy object in the memory.  
     * 
     * @param name name of the usecase policy.
     * @throws AccessManagementException
     */
    public void removeUsecasePolicy(String name) throws AccessManagementException;
    
    /**
     * Gets policy path.
     *
     * @throws AccessManagementException
     */
    public String getPath() throws AccessManagementException;

    /**
     * Gets parent policy.
     *
     * @throws AccessManagementException
     */
    public Policy getParentPolicy() throws AccessManagementException;

    /**
     * Check if inheritance shall be applied.
     *
     * @throws AccessManagementException
     */
    public boolean useInheritedPolicies();
    
    /**
     * Set if inheritance shall be applied.
     * @param useInheritedPolicies
     */
    public void setUseInheritedPolicies(boolean useInheritedPolicies);
}
