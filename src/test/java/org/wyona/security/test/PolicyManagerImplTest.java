package org.wyona.security.test;

import java.io.File;

import org.wyona.security.core.api.PolicyManager;
import org.wyona.security.core.api.Item;
import org.wyona.security.core.api.Usecase;
import org.wyona.security.core.api.User;
import org.wyona.security.core.api.Identity;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.security.impl.PolicyManagerImpl;
import org.wyona.security.impl.yarep.YarepIdentityManagerImpl;
import org.wyona.yarep.core.Repository;
import org.wyona.yarep.core.RepositoryFactory;

import junit.framework.TestCase;

/**
 * Test for the PolicyManager.
 */
public class PolicyManagerImplTest extends TestCase {

    protected Repository repo;
    protected PolicyManager policyManager;
    
    /**
     *
     */
    public void setUp() throws Exception {
        RepositoryFactory repoFactory = new RepositoryFactory();
        repo = repoFactory.newRepository("identities-repository", new File("repository1/config/repository.xml"));
        policyManager = new PolicyManagerImpl(repo);
    }
    
    /*
     * Test simple authorization
     */
    public void testAuthorization() throws Exception {
        RepositoryFactory repoFactory = new RepositoryFactory();
        Repository repoIdentities = repoFactory.newRepository("identities-repository", new File("repository2/repository.xml"));
        IdentityManager identityManager = new YarepIdentityManagerImpl(repoIdentities);

        User lenya = identityManager.getUserManager().getUser("lenya");
        User alice = identityManager.getUserManager().getUser("alice");

        assertFalse(policyManager.authorize("/hello", new Identity(alice), new Usecase("view")));
        assertTrue(policyManager.authorize("/hello", new Identity(lenya), new Usecase("view")));

        assertFalse(policyManager.authorize("/hello", new Identity(alice), new Usecase("read")));
        assertFalse(policyManager.authorize("/hello", new Identity(lenya), new Usecase("read")));
    }
}
