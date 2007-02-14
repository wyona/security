package org.wyona.security.impl.yarep;

import java.util.HashMap;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.ConfigurationException;
import org.apache.avalon.framework.configuration.DefaultConfiguration;
import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Group;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.security.core.api.Item;
import org.wyona.security.core.api.User;
import org.wyona.yarep.core.Node;

public class YarepGroup extends YarepItem implements Group {

    private HashMap members;

    public static final String MEMBERS = "members";

    public static final String MEMBER = "member";

    public static final String MEMBER_ID = "id";
    
    public static final String GROUP = "group";

    /**
     * Instantiates an existing YarepGroup from a repository node.
     * 
     * @param node
     */
    public YarepGroup(IdentityManager identityManager, Node node) throws AccessManagementException {
        super(identityManager, node); // this will call configure()
    }

    /**
     * Creates a new YarepGroup with the given id as a child of the given parent
     * node. The user is not saved.
     * 
     * @param parentNode
     * @param id
     * @throws AccessManagementException
     */
    public YarepGroup(IdentityManager identityManager, Node parentNode, String id, String name)
            throws AccessManagementException {
        super(identityManager, parentNode, id, name, id + ".gml");
        this.members = new HashMap();

    }

    protected void configure(Configuration config) throws ConfigurationException,
            AccessManagementException {
        setID(config.getAttribute(ID));
        setName(config.getChild(NAME, false).getValue());

        this.members = new HashMap();
        Configuration[] memberNodes = config.getChild(MEMBERS).getChildren("MEMBER");

        for (int i = 0; i < memberNodes.length; i++) {
            String id = memberNodes[i].getAttribute(MEMBER_ID);
            User user = getIdentityManager().getUserManager().getUser(id);
            addMember(user);
        }
    }

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
            membersNode.addChild(memberNode);
        }

        return config;
    }

    public void addMember(Item item) throws AccessManagementException {
        this.members.put(item.getID(), item);
    }

    public Item[] getMembers() throws AccessManagementException {
        return (Item[]) this.members.values().toArray(new Item[this.members.size()]);
    }

    public boolean isMember(Item item) throws AccessManagementException {
        return this.members.containsKey(item.getID());
    }

    public void removeMember(Item item) throws AccessManagementException {
        this.members.remove(item.getID());
    }

}