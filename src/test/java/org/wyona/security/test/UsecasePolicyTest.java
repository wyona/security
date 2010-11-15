package org.wyona.security.test;

import java.io.File;

import org.wyona.security.core.UsecasePolicy;
import org.wyona.security.core.GroupPolicy;
import org.wyona.security.core.api.Group;
import org.wyona.security.core.api.GroupManager;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.security.core.api.Identity;
import org.wyona.security.core.api.Item;
import org.wyona.security.core.api.User;
import org.wyona.security.core.api.UserManager;
import org.wyona.security.impl.yarep.YarepIdentityManagerImpl;
import org.wyona.yarep.core.Repository;
import org.wyona.yarep.core.RepositoryFactory;

import junit.framework.TestCase;

/**
 * Test for UsecasePolicy.
 */
public class UsecasePolicyTest extends TestCase {

    protected Repository repo;
    protected IdentityManager identityManager;

    /**
     *
     */
    public void setUp() throws Exception {
        RepositoryFactory repoFactory = new RepositoryFactory();
        repo = repoFactory.newRepository("identities-repository", new File("repository2/repository.xml"));
        identityManager = new YarepIdentityManagerImpl(repo, true);
    }

    /**
     * Test set and get name
     */
    public void testGetName() throws Exception {
        String usecaseName = "read";
        UsecasePolicy up = new UsecasePolicy(usecaseName);
        assertEquals(usecaseName, up.getName());
    }

    /**
     * Test add and get identities
     */
    public void testGetIdentities() throws Exception {
        String usecaseName = "read";
        UsecasePolicy up = new UsecasePolicy(usecaseName);
        String identityName = "alice";
        up.addIdentity(new Identity(identityName, "alice@foo.bar"), true);
        assertEquals(1, up.getIdentities().length);
        assertEquals(up.getIdentities()[0].getUsername(), identityName);
    }

    /**
     * Test get identity policies
     */
    public void testGetIdentityPolicies() throws Exception {
        String usecaseName = "read";
        UsecasePolicy up = new UsecasePolicy(usecaseName);
        up.addIdentity(new Identity("alice", "alice@foo.bar"), true);
        up.addIdentity(new Identity("bob", "bob@foo.bar"), false);
        assertEquals(2, up.getIdentityPolicies().length);
    }

    /**
     * Test add and get group policies
     */
    public void testGetGroupPolicies() throws Exception {
        String usecaseName = "read";
        UsecasePolicy up = new UsecasePolicy(usecaseName);
        up.addGroupPolicy(new GroupPolicy("administrators", true));
        up.addGroupPolicy(new GroupPolicy("reviewers", false));
        assertEquals(2, up.getGroupPolicies().length);
        assertEquals("reviewers", up.getGroupPolicies()[1].getId());
    }

    /**
     * Test get identity policy
     */
    public void testGetIdentityPolicy() throws Exception {
        String usecaseName = "read";
        UsecasePolicy up = new UsecasePolicy(usecaseName);
        up.addIdentity(new Identity("alice", "alice@foo.bar"), true);
        Identity bob = new Identity("bob", "bob@foo.bar");
        up.addIdentity(bob, false);
        assertEquals("bob", up.getIdentityPolicy(bob).getIdentity().getUsername());
    }

    /**
     * Test get group policy
     */
    public void testGetGroupPolicy() throws Exception {
        String usecaseName = "read";
        UsecasePolicy up = new UsecasePolicy(usecaseName);
        up.addGroupPolicy(new GroupPolicy("administrators", true));
        up.addGroupPolicy(new GroupPolicy("reviewers", false));
        assertEquals(2, up.getGroupPolicies().length);
        assertEquals("reviewers", up.getGroupPolicy("reviewers").getId());
    }

    /**
     * Test remove identity policy
     */
    public void testRemoveIdentityPolicy() throws Exception {
        String usecaseName = "read";
        UsecasePolicy up = new UsecasePolicy(usecaseName);
        up.addIdentity(new Identity("alice", "alice@foo.bar"), true);
        Identity bob = new Identity("bob", "bob@foo.bar");
        up.addIdentity(bob, false);
        assertEquals(2, up.getIdentityPolicies().length);
        assertEquals("bob", up.getIdentityPolicy(bob).getIdentity().getUsername());
        up.removeIdentityPolicy(bob);
        assertEquals(1, up.getIdentityPolicies().length);
    }

    /**
     * Test remove group policy
     */
    public void testRemoveGroupPolicy() throws Exception {
        String usecaseName = "read";
        UsecasePolicy up = new UsecasePolicy(usecaseName);
        up.addGroupPolicy(new GroupPolicy("editors", true));
        up.addGroupPolicy(new GroupPolicy("reviewers", true));
        assertEquals(2, up.getGroupPolicies().length);
        up.removeGroupPolicy("editors");
        assertEquals(1, up.getGroupPolicies().length);
    }

    /**
     * Test merge usecase policies
     */
    public void testMergeUsecasePolicies() throws Exception {
        String usecaseName = "read";

        UsecasePolicy up1 = new UsecasePolicy(usecaseName);
        up1.addGroupPolicy(new GroupPolicy("editors", true));
        up1.addIdentity(new Identity("alice", "alice@foo.bar"), true);
        up1.addGroupPolicy(new GroupPolicy("reviewers", true));
        assertEquals(2, up1.getGroupPolicies().length);

        UsecasePolicy up2 = new UsecasePolicy(usecaseName);
        up2.addGroupPolicy(new GroupPolicy("administrators", true));
        up2.addGroupPolicy(new GroupPolicy("reviewers", false));
        assertEquals(2, up2.getGroupPolicies().length);
        up2.addIdentity(new Identity("bob", "bob@foo.bar"), true);
        up2.addIdentity(new Identity("alice", "alice@foo.bar"), true);

        up1.merge(up2); // INFO: Merge does ignore group or identity policies with the same name
        assertEquals(3, up1.getGroupPolicies().length);
        assertEquals(2, up1.getIdentityPolicies().length);
    }
}
