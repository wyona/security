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
public class YarepUserManagerImplTest extends TestCase {

    private static Logger log = Logger.getLogger(YarepUserManagerImplTest.class);

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
}
