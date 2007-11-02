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
        log.error("Not implemented yet!");
        String repoPath = configuration.getDocumentElement().getNodeValue();
        log.error("DEBUG: Configuration: " + repoPath);
        try {
            return new PolicyManagerImplVersion2(new RepositoryFactory().newRepository("hugo", new File(repoPath)));
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }
}
