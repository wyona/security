package org.wyona.security.core.api;

/**
 * A policy interface.
 */
public interface Policy {
    /**
     * Gets the usecases/actions of policies.
     *
     * @return usecases declared within this policy
     */
    public void getUsecases();

    /**
     * Adds a usecase to this policy. TBD: What if such a usecase already exists?
     *
     * @param usecase Usecase
     * @throws AccessManagementException
     */
    public void addUsecase(String usecase) throws AccessManagementException;

    /**
     * Gets parent policy.
     *
     * @throws AccessManagementException
     */
    public Policy getParentPolicy() throws AccessManagementException;
}
