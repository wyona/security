package org.wyona.security.impl.yarep;

import org.apache.log4j.Logger;
import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.DefaultConfigurationBuilder;

import java.util.List;
import java.util.LinkedList;
import java.util.Iterator;
import java.lang.UnsupportedOperationException;

import org.wyona.security.core.api.User;
import org.wyona.security.core.api.IdentityManager;
import org.wyona.security.core.api.AccessManagementException;

import org.wyona.yarep.core.Node;
import org.wyona.yarep.core.Repository;
import org.wyona.yarep.core.search.Searcher;

/**
 * Yarep users iterator.
 * Warning! This implementation does not scale, because
 * Yarep doesn't have the ability to give us an Iterator.
 * Therefore, we have to request all nodes in an array,
 * which somehow defeats the purpose of this iterator.
 * But until Yarep gains that capability, we're don't
 * have much of a choice.
 */
public class YarepUsersIterator extends YarepUserManager implements java.util.Iterator {
    // Constants
    private static Logger log = Logger.getLogger(YarepUsersIterator.class);
    private static DefaultConfigurationBuilder configBuilder = new DefaultConfigurationBuilder(true);

    // Variables
    private int totalUsers;
    private int currentUser;
    private List<Node> userNodeList;
    private Iterator<Node> listIterator;

    /**
     * Constructor.
     */
    public YarepUsersIterator(IdentityManager identityManager, 
                              Repository identitiesRepository, 
                              boolean cacheEnabled, 
                              boolean resolveGroupsAtCreation) 
                              throws AccessManagementException {
        // Call parent
        super(identityManager, identitiesRepository, cacheEnabled, resolveGroupsAtCreation);
        log.info("Load users from repository '" + identitiesRepository.getConfigFile() + "'");

        // TODO: This is inefficient! If Yarep were able to
        // return an iterator instead of an array, this could
        // be done in a more effective manner, but until Yarep
        // gains that capability we're currently stuck like this.
        try {
            Node usersParentNode = super.getUsersParentNode();
            Node[] userNodes = usersParentNode.getNodes();

            userNodeList = new LinkedList<Node>();
            for(Node n : userNodes) {
                if(n.isResource()) {
                    userNodeList.add(n);
                }
            }

            listIterator = userNodeList.listIterator();
        } catch(Exception e) {
            String errorMsg = "Could not read users from repository: " + e.getMessage();
            log.error(errorMsg, e);
            throw new AccessManagementException(errorMsg, e);
        }
    }

    /**
     * Constructor with search query.
     */
    public YarepUsersIterator(IdentityManager identityManager, 
                              Repository identitiesRepository, 
                              boolean cacheEnabled, 
                              boolean resolveGroupsAtCreation,
                              String query) 
                              throws AccessManagementException {
        // Call parent
        super(identityManager, identitiesRepository, cacheEnabled, resolveGroupsAtCreation);
        log.info("Load users from repository '" + identitiesRepository.getConfigFile() + "'");

        // TODO: This is inefficient! If Yarep were able to
        // return an iterator instead of an array, this could
        // be done in a more effective manner, but until Yarep
        // gains that capability we're currently stuck like this.
        try {
            Searcher s = identitiesRepository.getSearcher();
            Node[] userNodes = s.search(query);

            userNodeList = new LinkedList<Node>();
            for(Node n : userNodes) {
                if(n.isResource()) {
                    userNodeList.add(n);
                }
            }

            listIterator = userNodeList.listIterator();
        } catch(Exception e) {
            String errorMsg = "Could not read users from repository: " + e.getMessage();
            log.error(errorMsg, e);
            throw new AccessManagementException(errorMsg, e);
        }
    }

    /**
     * @see java.util.Iterator#hasNext()
     */
    @Override
    public boolean hasNext() {
        return listIterator.hasNext();
    }

    /**
     * @see java.util.Iterator#next()
     */
    @Override
    public Object next() {
        Node n = listIterator.next();
        try {
            Configuration config = configBuilder.build(n.getInputStream());
            // Also support identity for backwards compatibility
            if(config.getName().equals(YarepUser.USER) || config.getName().equals("identity")) {
                User user = super.constructUser(this.identityManager, n);
                log.debug("User (re)loaded: " + n.getName() + ", " + user.getID());
                return user;
            }
        } catch(Exception e) {
            // We can't throw an exception here, if this user
            // is invalid/broken we'll just have to return null.
            log.error(e.getMessage(), e);
        }

        return null;
    }

    /**
     * @see java.util.Iterator#remove()
     */
    @Override
    public void remove() throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Not implemented.");
    }
}
