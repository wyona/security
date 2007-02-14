package org.wyona.security.core.api;

/**
 * A host machine.
 */
public interface Host extends Item {
    /**
     * Gets the ip number of this host.
     * 
     * @return ip as string
     * @throws AccessManagementException
     */
    String getIP() throws AccessManagementException;

    /**
     * Sets the ip number of this host. The host is not automatically saved.
     * 
     * @param ip
     *            ip as string
     * @throws AccessManagementException
     */
    void setIP(String ip) throws AccessManagementException;
}