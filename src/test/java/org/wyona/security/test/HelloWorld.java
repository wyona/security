package org.wyona.security.test;

import org.wyona.security.core.PolicyManagerFactory;
import org.wyona.security.core.api.PolicyManager;
import org.wyona.security.core.api.Role;
import org.wyona.security.core.api.Identity;

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

        Path path = null;

        path = new Path("/hello/world.html");
        String[] groupnames = {"hello", "sugus"};
        if (pm.authorize(path, new Identity("lenya", groupnames), new Role("view"))) {
            System.out.println("Access granted: " + path);
        } else {
            System.out.println("Access denied: " + path);
        }

        path = new Path("/");
        if (pm.authorize(path, null, null)) {
            System.out.println("Access granted: " + path);
        } else {
            System.out.println("Access denied: " + path);
        }

        path = new Path("/hello");
        if (pm.authorize(path, new Identity("lenya", null), new Role("read"))) {
            System.out.println("Access granted: " + path);
        } else {
            System.out.println("Access denied: " + path);
        }

        path = new Path("/hello/");
        if (pm.authorize(path, null, null)) {
            System.out.println("Access granted: " + path);
        } else {
            System.out.println("Access denied: " + path);
        }
    }
}
