package org.wyona.security.core.api;

import org.wyona.security.core.UsecasePolicy;

/**
 * A policy interface.
 */
public interface Policy {
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
     * Gets parent policy.
     *
     * @throws AccessManagementException
     */
    public Policy getParentPolicy() throws AccessManagementException;
}
