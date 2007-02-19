package org.wyona.security.impl.yarep;

import java.util.ArrayList;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.ConfigurationException;
import org.apache.avalon.framework.configuration.DefaultConfiguration;
import org.wyona.security.core.api.AccessManagementException;
import org.wyona.security.core.api.Group;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.security.core.api.User;
import org.wyona.security.impl.Password;
import org.wyona.yarep.core.Node;

public class YarepUser extends YarepItem implements User {

    public static final String USER = "user";

    public static final String EMAIL = "email";

    public static final String PASSWORD = "password";

    protected String email;

    protected String password;

    /**
     * Instantiates an existing YarepUser from a repository node.
     * 
     * @param node
     */
    public YarepUser(IdentityManager identityManager, Node node) throws AccessManagementException {
        super(identityManager, node); // this will call configure()
    }

    /**
     * Creates a new YarepUser with the given id as a child of the given parent
     * node. The user is not saved.
     * 
     * @param parentNode
     * @param id
     * @throws AccessManagementException
     */
    public YarepUser(IdentityManager identityManager, Node parentNode, String id, String name,
            String email, String password) throws AccessManagementException {
        super(identityManager, parentNode, id, name, id + ".xml");
        setEmail(email);
        setPassword(password);
    }

    protected void configure(Configuration config) throws ConfigurationException,
            AccessManagementException {
        setID(config.getAttribute(ID));
        setName(config.getChild(NAME, false).getValue());
        setEmail(config.getChild(EMAIL, false).getValue());
        this.password = config.getChild(PASSWORD, false).getValue();
    }

    protected Configuration createConfiguration() throws AccessManagementException {
        DefaultConfiguration config = new DefaultConfiguration(USER);
        config.setAttribute(ID, getID());
        DefaultConfiguration nameNode = new DefaultConfiguration(NAME);
        nameNode.setValue(getName());
        config.addChild(nameNode);
        DefaultConfiguration emailNode = new DefaultConfiguration(EMAIL);
        emailNode.setValue(getEmail());
        config.addChild(emailNode);
        DefaultConfiguration passwordNode = new DefaultConfiguration(PASSWORD);
        passwordNode.setValue(getPassword());
        config.addChild(passwordNode);

        return config;
    }

    public boolean authenticate(String password) throws AccessManagementException {
        return getPassword().equals(Password.getMD5(password));
    }

    public String getEmail() throws AccessManagementException {
        return this.email;
    }

    public Group[] getGroups() throws AccessManagementException {
        Group[] allGroups = getIdentityManager().getGroupManager().getGroups();
        ArrayList groups = new ArrayList();
        for (int i = 0; i < allGroups.length; i++) {
            if (allGroups[i].isMember(this)) {
                groups.add(allGroups[i]);
            }
        }
        return (Group[]) groups.toArray(new Group[groups.size()]);
    }

    public void setEmail(String email) throws AccessManagementException {
        this.email = email;

    }

    public void setPassword(String password) throws AccessManagementException {
        this.password = Password.getMD5(password);
    }

    protected String getPassword() throws AccessManagementException {
        return this.password;
    }

}