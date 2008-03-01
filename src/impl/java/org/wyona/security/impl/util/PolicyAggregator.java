package org.wyona.security.impl.util;

import org.wyona.security.core.AuthorizationException;
import org.wyona.security.core.api.Policy;
import org.wyona.security.core.api.PolicyManager;
/*
import org.wyona.security.core.GroupPolicy;
import org.wyona.security.core.UsecasePolicy;
import org.wyona.security.core.api.Identity;
*/

import org.wyona.commons.io.PathUtil;

import org.apache.log4j.Logger;

/**
 * Utility class to aggregate policies based on their parent policies
 */
public class PolicyAggregator {

    private static Logger log = Logger.getLogger(PolicyAggregator.class);

    /**
     *
     */
    public static Policy aggregatePolicy(Policy policy) throws AuthorizationException {
        return policy;
    }

    /**
     *
     */
    public static Policy aggregatePolicy(String path, PolicyManager pm) throws AuthorizationException {
        Policy policy = pm.getPolicy(path, false);
        if (policy == null) {
            if (!path.equals("/")) {
                return aggregatePolicy(PathUtil.getParent(path), pm);
            } else {
                log.warn("No policies found at all, not even a root policy!");
                return null;
            }
        } else {
            if (!policy.useInheritedPolicies()) {
                return policy;
            } else {
                if (!path.equals("/")) {
                    Policy parentPolicy = aggregatePolicy(PathUtil.getParent(path), pm);
                    // TODO: Aggregate this policy with parent policy
                    log.warn("TODO: Aggregate policy " + path + " with parent " + PathUtil.getParent(path));
                    return policy;
                } else {
                    return policy;
                }
            }
        }
    }
}
