package org.wyona.security.test;

import java.io.File;

import org.wyona.security.core.api.Group;
import org.wyona.security.core.api.GroupManager;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.security.core.api.Item;
import org.wyona.security.core.api.User;
import org.wyona.security.core.api.UserManager;
import org.wyona.security.impl.yarep.YarepIdentityManagerImpl;
import org.wyona.yarep.core.Repository;
import org.wyona.yarep.core.RepositoryFactory;

import junit.framework.TestCase;

import org.apache.log4j.Logger;

/**
 * Test of YarepGroup implementation
 */
public class YarepGroupImplTest extends TestCase {

    private static Logger log = Logger.getLogger(YarepGroupImplTest.class);

    private Repository repo;
    private IdentityManager identityManager;

    /**
     * Init identity manager
     */
    public void setUp() throws Exception {
        RepositoryFactory repoFactory = new RepositoryFactory();
        repo = repoFactory.newRepository("repository2", new File("repository2/repository.xml"));

        identityManager = new YarepIdentityManagerImpl(repo, false);
    }

    /**
     * Test to get an individual user
     */
    public void testGetUser() throws Exception {
        User user = identityManager.getUserManager().getUser("lenya");
        assertNotNull(user);
        assertEquals("lenya@wyona.org", user.getEmail());
    }

    /**
     * Test to get all parent groups of an individual user
     */
    public void testGetAllParentGroupsOfUser() throws Exception {
        User user = identityManager.getUserManager().getUser("lenya");
        assertNotNull(user);
        assertEquals("lenya@wyona.org", user.getEmail());

        Group[] parentGroups = user.getGroups(true);
        assertEquals(parentGroups.length, 3);

        String[] parentGroupIDs = user.getGroupIDs(true);
        assertEquals(parentGroupIDs.length, 3);
    }

    /**
     * Test to migrate groups index of an individual user of a previous version
     */
    public void testMigrateGroupsIndex() throws Exception {
        User user = identityManager.getUserManager().getUser("user-without-groups-index");
        assertNotNull(user);
        assertEquals(user.getGroupIDs(false).length, 0);
    }

    /**
     * Test to get an individual group
     */
    public void testGetGroup() throws Exception {
        Group group = identityManager.getGroupManager().getGroup("editor");
        assertNotNull(group);
        assertEquals("Editors", group.getName());
    }

    /**
     * Test to get the groups of an individual user
     */
    public void testGetGroupsOfUser() throws Exception {
        User user = identityManager.getUserManager().getUser("lenya");
        assertNotNull(user);
        assertEquals("lenya@wyona.org", user.getEmail());
        Group[] groups = user.getGroups();
        assertNotNull(groups);
        assertEquals(groups.length, 1);
        assertEquals(groups[0].getName(), "Editors");
    }

    /**
     * Test to add a user to a group
     */
    public void testAddUserToGroup() throws Exception {
        String userID = "user" + new java.util.Date().getTime();
        log.warn("DEBUG: User ID: " + userID);
        User user = identityManager.getUserManager().createUser(userID, "Sugus", "sugus@wyona.org", "gugus");
        assertNotNull(user);

        String groupID = "group" + new java.util.Date().getTime();
        log.warn("DEBUG: Group ID: " + groupID);
        Group group = identityManager.getGroupManager().createGroup(groupID, "Gugus");
        assertNotNull(group);

        group.addMember(user);
        group.save();
        String[] groupIDs = user.getGroupIDs(true);
        assertEquals(groupIDs[0], groupID);
    }

    /**
     * Test to remove a user from an individual group
     */
    public void testRemoveUserFromGroup() throws Exception {
        User user = identityManager.getUserManager().getUser("lenya");
        assertNotNull(user);
        assertEquals("lenya@wyona.org", user.getEmail());

        Group group = identityManager.getGroupManager().getGroup("editor");
        assertNotNull(group);
        assertEquals("Editors", group.getName());

        group.removeMember(user);
        group.save();
        String[] groupIDs = user.getGroupIDs(true);
        assertEquals(groupIDs.length, 0);
    }

    /**
     * Test to add a group to a group
     */
    public void testAddGroupToGroup() throws Exception {
        String groupID = "group" + new java.util.Date().getTime();
        log.warn("DEBUG: Group ID: " + groupID);
        Group group = identityManager.getGroupManager().createGroup(groupID, "Gugus");
        assertNotNull(group);

        String groupID2 = "group2" + new java.util.Date().getTime();
        log.warn("DEBUG: Group ID: " + groupID2);
        Group group2 = identityManager.getGroupManager().createGroup(groupID2, "Sugus");
        assertNotNull(group2);

        group.addMember(group2);
        group.save();
        Group[] parentGroups = group2.getParents();
        assertEquals(parentGroups[0].getID(), groupID);
    }

    /**
     * Test to remove a group from a group
     */
    public void testRemoveGroupFromGroup() throws Exception {
        String groupID = "group" + new java.util.Date().getTime();
        log.warn("DEBUG: Group ID: " + groupID);
        Group group = identityManager.getGroupManager().createGroup(groupID, "Gugus");
        assertNotNull(group);

        String groupID2 = "group2" + new java.util.Date().getTime();
        log.warn("DEBUG: Group ID: " + groupID2);
        Group group2 = identityManager.getGroupManager().createGroup(groupID2, "Sugus");
        assertNotNull(group2);

        group.addMember(group2);
        group.save();
        Group[] parentGroups = group2.getParents();
        assertEquals(parentGroups[0].getID(), groupID);

        group.removeMember(group2);
        group.save();
        parentGroups = group2.getParents();
        if (parentGroups != null) {
            assertEquals(parentGroups.length, 0);
        } else {
            assertNull(parentGroups);   
        }
    }
}
