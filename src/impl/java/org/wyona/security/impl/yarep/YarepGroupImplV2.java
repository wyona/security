package org.wyona.security.impl.yarep;

import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Group;
import org.wyona.security.core.api.Item;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

/**
 * Group implementation based on Yarep, version 2, improving scalability issues of version 1 (YarepGroup.class)
 * Also see http://www.grantingersoll.com/2007/01/23/processing-a-large-number-of-files-in-java/
 */
public class YarepGroupImplV2 extends AbstractYarepGroup implements Group {

    private static final Logger log = LogManager.getLogger(YarepGroupImplV2.class);

    private String name;
    
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
        if (id != null) {
            return id;
        } else {
            if (node != null) {
                try {
                    log.warn("TODO: Get ID from persistent repository: " + node.getPath());
                } catch(Exception e) {
                    log.error(e, e);
                }
                return null;
            } else {
                log.error("Neither ID nor yarep node available for group!");
                return null;
            }
        }
    }

    /**
     * @see org.wyona.security.core.api.Item#getName()
     */
    public String getName() throws AccessManagementException {
        if (name != null) {
            return name;
        } else {
            if (node != null) {
                try {
                    log.warn("TODO: Get name from persistent repository: " + node.getPath());
                } catch(Exception e) {
                    log.error(e, e);
                }
                return null;
            } else {
                log.error("Neither name nor yarep node available for group with ID: " + id);
                return null;
            }
        }
    }

    /**
     * @see org.wyona.security.core.api.Item#setName(String)
     */
    public void setName(String name) throws AccessManagementException {
        this.name = name;
        log.warn("TODO: Save persistently...");
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
