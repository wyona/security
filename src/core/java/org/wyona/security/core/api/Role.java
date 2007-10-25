package org.wyona.security.core.api;

/**
 * @deprecated Use Usecase instead
 */
public class Role {

    protected String name;

    /**
     *
     */
    public Role(String name) {
        this.name = name;
    }

    /**
     *
     */
    public String getName() {
        return name;
    }
}
