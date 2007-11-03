package org.wyona.security.impl;

import org.w3c.dom.Document;

import org.wyona.security.core.PolicyManagerFactory;
import org.wyona.security.core.api.PolicyManager;
import org.wyona.yarep.core.Repository;
import org.wyona.yarep.core.RepositoryFactory;

import org.apache.log4j.Category;

import java.io.File;

/**
 *
 */
public class PolicyManagerFactoryImplVersion2 extends PolicyManagerFactory {

    private static Category log = Category.getInstance(PolicyManagerFactoryImplVersion2.class);

    /**
     *
     */
    public PolicyManager newPolicyManager(Repository policiesRepository) {
        return new PolicyManagerImplVersion2(policiesRepository);
    }

    /**
     *
     */
    public PolicyManager newPolicyManager(Document configuration, javax.xml.transform.URIResolver resolver) {
        if (log.isDebugEnabled()) log.debug("Configuration Root Name: " + configuration.getDocumentElement().getLocalName());
        String repoPath = configuration.getDocumentElement().getFirstChild().getNodeValue();
        if (log.isDebugEnabled()) log.debug("Repo path: " + repoPath);

        try {
            String base = null;
            String resolvedRepoPath = resolver.resolve(repoPath, base).getSystemId();
            if (log.isDebugEnabled()) log.debug("Resolved repo path: " + resolvedRepoPath);
            return new PolicyManagerImplVersion2(new RepositoryFactory().newRepository("policy-repo-v2", new File(resolvedRepoPath)));

            // NOTE: Repo factory will automagically resolve a relative path with respect to the classpath, but this is not necessarily how it should be. In case of realm it should be relative to the realm configuration, hence the resolver!
            //return new PolicyManagerImplVersion2(new RepositoryFactory().newRepository("policy-repo-v2", new File(repoPath)));
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }
}
