package org.wyona.security.core.api;

/**
 *
 */
public interface PolicyManager {

    /**
     *
     */
    public boolean authorize(String path, String idenitity, String role);
}
