package org.wyona.security.test;


import java.io.File;

import org.wyona.security.core.api.IdentityManager;
import org.wyona.security.impl.IdentityManagerImpl;
import org.wyona.yarep.core.Repository;
import org.wyona.yarep.core.RepositoryFactory;

import junit.framework.TestCase;

/**
 * Test for the IdentityManager.
 */
public class IdentityManagerImplTest extends TestCase {

    protected Repository repo;
    protected IdentityManager identityManager;
    
    public void setUp() throws Exception {
        RepositoryFactory repoFactory = new RepositoryFactory();
        repo = repoFactory.newRepository("identities-repository", new File(
                "config/repository-identities.xml"));
        identityManager = new IdentityManagerImpl(repo);
    }
    
    public void testAuthenticate() throws Exception {
        String user = "lenya";
        String rightPassword = "levi";
        String wrongPassword = "lala";
        assertTrue(identityManager.authenticate(user, rightPassword));
        assertFalse(identityManager.authenticate(user, wrongPassword));
    }
}
