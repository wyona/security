package org.wyona.security.impl.yarep;

import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Group;
import org.wyona.security.core.api.Item;

import org.apache.log4j.Logger;

/**
 * Group implementation based on Yarep, version 2, improving scalability issues of version 1 (YarepGroup.class)
 */
public class YarepGroupImplV2 implements Group {

    private static final Logger log = Logger.getLogger(YarepGroupImplV2.class);
    
    /**
     *
     */
    public YarepGroupImplV2() throws AccessManagementException {
        log.warn("DEBUG: Init...");
    }

    /**
     * @see org.wyona.security.core.api.Item#getID()
     */
    public String getID() throws AccessManagementException {
        log.warn("TODO: Finish implementation...");
        return null;
    }

    /**
     * @see org.wyona.security.core.api.Item#getName()
     */
    public String getName() throws AccessManagementException {
        log.warn("TODO: Finish implementation...");
        return null;
    }

    /**
     * @see org.wyona.security.core.api.Item#setName(String)
     */
    public void setName(String name) throws AccessManagementException {
        log.warn("TODO: Finish implementation...");
    }

    /**
     * @see org.wyona.security.core.api.Item#delete()
     */
    public void delete() throws AccessManagementException {
        log.warn("TODO: Finish implementation...");
    }

    /**
     * @see org.wyona.security.core.api.Item#save()
     */
    public void save() throws AccessManagementException {
        log.warn("TODO: Finish implementation...");
    }

    /**
     * @see org.wyona.security.core.api.Group#getParents()
     */
    public Group[] getParents() throws AccessManagementException {
        log.warn("TODO: Finish implementation...");
        return null;
    }

    /**
     * @see org.wyona.security.core.api.Group#getMembers()
     */
    public Item[] getMembers() throws AccessManagementException {
        log.warn("TODO: Finish implementation...");
        return null;
    }

    /**
     * @see org.wyona.security.core.api.Group#addMember(Item)
     */
    public void addMember(Item item) throws AccessManagementException {
        log.warn("TODO: Finish implementation...");
    }

    /**
     * @see org.wyona.security.core.api.Group#removeMember(Item)
     */
    public void removeMember(Item item) throws AccessManagementException {
        log.warn("TODO: Finish implementation...");
    }

    /**
     * @see org.wyona.security.core.api.Group#isMember(Item)
     */
    public boolean isMember(Item item) throws AccessManagementException {
        log.warn("TODO: Finish implementation...");
        return false;
    }
}
