package org.wyona.security.test;

import org.wyona.security.core.PolicyManagerFactory;
import org.wyona.security.core.api.PolicyManager;

import org.wyona.commons.io.Path;

/**
 *
 */
public class HelloWorld {

    /**
     *
     */
    public static void main(String[] args) {
        System.out.println("Hello World!");

        PolicyManagerFactory pmf = PolicyManagerFactory.newInstance();
        PolicyManager pm = pmf.newPolicyManager();

        Path path = new Path("/hello/world.html");
        if (pm.authorize(path, null, null)) {
            System.out.println("Access granted: " + path);
        } else {
            System.out.println("Access denied: " + path);
        }
    }
}
