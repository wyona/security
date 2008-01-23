package org.wyona.security.core;

import org.wyona.security.core.api.Identity;

/**
 *
 */
public class UsecasePolicy {

    private String name;

    /**
     *
     */
    public UsecasePolicy(String name) {
        this.name = name;
    }

    /**
     *
     */
    public String getName() {
        return name;
    }

    /**
     *
     */
    public Identity getIdentities() {
        return null;
    }
}
