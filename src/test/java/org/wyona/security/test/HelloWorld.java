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

        path = new Path("/hello/sugus.txt");
        if (pm.authorize(path, new Identity("alice", null), new Role("touch"))) {
            System.out.println("Access granted: " + path);
        } else {
            System.out.println("Access denied: " + path);
        }

        java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(System.in));
        try {
            System.out.println("Please enter a path (e.g. /hello/world.txt):");
            String value = br.readLine();
            if (value.equals("")) {
                System.out.println("No path has been specified!");
                return;
            }
            System.out.println("The following value has been entered: " + value);
            path = new Path(value);

            System.out.println("Please enter a username (e.g. lenya):");
            value = br.readLine();
            if (value.equals("")) {
                System.out.println("No username has been specified!");
                return;
            }
            System.out.println("The following value has been entered: " + value);
            Identity identity = new Identity(value, null);

            System.out.println("Please enter a role (e.g. view):");
            value = br.readLine();
            if (value.equals("")) {
                System.out.println("No role has been specified!");
                return;
            }
            System.out.println("The following value has been entered: " + value);
            Role role = new Role(value);

            if (pm.authorize(path, identity, role)) {
                System.out.println("Access granted: " + path);
            } else {
                System.out.println("Access denied: " + path);
            }
        } catch (Exception e) {
            System.err.println(e);
        }
    }
}
