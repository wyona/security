package org.wyona.security.impl.yarep;

import java.util.Vector;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.ConfigurationException;
import org.apache.avalon.framework.configuration.DefaultConfiguration;
import org.apache.log4j.Logger;

import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Group;
import org.wyona.security.core.api.UserManager;
import org.wyona.security.core.api.GroupManager;
import org.wyona.security.core.api.Item;
import org.wyona.security.core.api.User;

import org.wyona.yarep.core.Node;

/**
 * Group implementation based on Yarep
 */
public class YarepGroup extends YarepItem implements Group {
    protected static final Logger log = Logger.getLogger(YarepGroup.class);
    
    private Vector members;
    private Vector parents;

    public static final String MEMBERS = "members";

    public static final String MEMBER = "member";

    public static final String MEMBER_ID = "id";
    private static final String MEMBER_TYPE = "type";
    private static final String USER_TYPE = "user";
    private static final String GROUP_TYPE = "group";
    
    public static final String GROUP = "group";

    /**
     * Instantiates an existing YarepGroup from a repository node.
     * 
     * @param userManager
     * @param groupManager
     * @param node
     * @throws AccessManagementException
     */
    public YarepGroup(UserManager userManager, GroupManager groupManager, Node node) throws AccessManagementException {
        super(userManager, groupManager, node); // this will call configure()
    }

    /**
     *
     */
    public YarepGroup(UserManager userManager, GroupManager groupManager, String id, String name) {
        super(userManager, groupManager, id, name);
        this.members = new Vector();
        this.parents = new Vector();
    }

    /**
     * @see org.wyona.security.impl.yarep.YarepItem#configure(org.apache.avalon.framework.configuration.Configuration)
     */
    protected void configure(Configuration config) throws ConfigurationException, AccessManagementException {
        setID(config.getAttribute(ID));
        setName(config.getChild(NAME, false).getValue());

        this.members = new Vector();
        this.parents = new Vector();
        Configuration[] memberNodes = config.getChild(MEMBERS).getChildren(MEMBER);

        for (int i = 0; i < memberNodes.length; i++) {
            String id = memberNodes[i].getAttribute(MEMBER_ID);
            // type attribute is optional and helps to differentiate between users and groups
            String type = memberNodes[i].getAttribute(MEMBER_TYPE, USER_TYPE);
            if (type.equals(USER_TYPE)) {
                if (getUserManager() != null) {
                    if (getUserManager().existsUser(id)) {
                        User user = getUserManager().getUser(id);
                        addMember(user);
                    } else {
                        log.warn("No user with id '" + id + "' exists, but is referenced within group '" + getID() + "' (" + getName() + ")");
                    }
                } else {
                    log.error("User manager is NULL! User " + id + " cannot be added to group " + getID());
                }
            } else if (type.equals(GROUP_TYPE)) {
                log.warn("Beware of loops when adding groups within groups!");
                if (getGroupManager() != null) {
                    if (getGroupManager().existsGroup(id)) {
                        Group group = getGroupManager().getGroup(id);
                        addMember(group);
                    } else {
                        log.warn("No group with id '" + id + "' exists, but is referenced within group '" + getID() + "' (" + getName() + ")");
                    }
                } else {
                    log.error("Group manager is NULL! Group " + id + " cannot be added to group " + getID());
                }
            } else {
                log.error("No such member/item type: " + type);
            }
        }
    }

    /**
     * @see org.wyona.security.impl.yarep.YarepItem#createConfiguration()
     */
    protected Configuration createConfiguration() throws AccessManagementException {
        DefaultConfiguration config = new DefaultConfiguration(GROUP);
        config.setAttribute(ID, getID());
        DefaultConfiguration nameNode = new DefaultConfiguration(NAME);
        nameNode.setValue(getName());
        config.addChild(nameNode);

        DefaultConfiguration membersNode = new DefaultConfiguration(MEMBERS);
        config.addChild(membersNode);

        Item[] items = getMembers();

        for (int i = 0; i < items.length; i++) {
            DefaultConfiguration memberNode = new DefaultConfiguration(MEMBER);
            memberNode.setAttribute(MEMBER_ID, items[i].getID());
            if (items[i] instanceof Group) {
                memberNode.setAttribute(MEMBER_TYPE, "group");
            } else if (items[i] instanceof User) {
                memberNode.setAttribute(MEMBER_TYPE, "user");
            } else {
                log.error("Item is neither user nor group: " + items[i].getID());
            }
            membersNode.addChild(memberNode);
        }

        return config;
    }

    /**
     * @see org.wyona.security.core.api.Group#addMember(org.wyona.security.core.api.Item)
     */
    public void addMember(Item item) throws AccessManagementException {
        if (null != item){
            this.members.add(item);
        } else {
            log.warn("Item is null. Can't add item/user to the group '" + getID() + "'");
        }
    }

    /**
     * @see org.wyona.security.core.api.Group#getParents()
     */
    public Group[] getParents() throws AccessManagementException {
        log.error("TODO: Set parent not implemented yet!");
        Group[] g = new Group[parents.size()];
        for (int i = 0; i < g.length; i++) {
            g[i] = (Group) parents.elementAt(i);
        }
        return g;
    }

    /**
     * @see org.wyona.security.core.api.Group#getMembers()
     */
    public Item[] getMembers() throws AccessManagementException {
        Item[] m = new Item[members.size()];
        for (int i = 0; i < m.length; i++) {
            m[i] = (Item) members.elementAt(i);
        }
        return m;
    }

    /**
     * @see org.wyona.security.core.api.Group#isMember(org.wyona.security.core.api.Item)
     */
    public boolean isMember(Item item) throws AccessManagementException {
        return item != null && this.members.contains(item);
    }

    /**
     * @see org.wyona.security.core.api.Group#removeMember(org.wyona.security.core.api.Item)
     */
    public void removeMember(Item item) throws AccessManagementException {
        if (null != item) {
            this.members.remove(item);
            log.warn("Member has been removed: " + item.getID());
        } else {
            log.warn("Item is null. Can't remove item/user from the group '" + getID() + "'");
        }
    }
}
