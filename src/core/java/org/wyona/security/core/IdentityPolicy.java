package org.wyona.security.core;

import org.wyona.security.core.api.Identity;

/**
 * {@inheritDoc}
 * 
 * The XML representation of an IdentityPolicy is e.g. {@code <user id="lenya" permission="false"/>}.
 */
public class IdentityPolicy extends ItemPolicy {

    private Identity identity;

    public IdentityPolicy(Identity identity, boolean permission) {
        super(permission);
        this.identity = identity;
    }

    /**
     * Gets the identity associated with this policy.
     */
    public Identity getIdentity() {
        return identity;
    }

    @Override
    public String getId() {
        return identity.getUsername();
    }
}
