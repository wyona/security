package org.wyona.security.core;

import org.wyona.security.core.api.Identity;

/**
 *
 */
public class IdentityPolicy {

    private Identity identity;
    private boolean permission;

    /**
     *
     */
    public IdentityPolicy(Identity identity) {
        this.identity = identity;
        this.permission = true;
    }

    /**
     *
     */
    public IdentityPolicy(Identity identity, boolean permission) {
        this.identity = identity;
        this.permission = permission;
    }

    /**
     *
     */
    public Identity getIdentity() {
        return identity;
    }

    /**
     *
     */
    public boolean getPermission() {
        return permission;
    }
}
