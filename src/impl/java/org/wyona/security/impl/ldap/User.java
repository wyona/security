package org.wyona.security.impl.ldap;

/**
 *
 */
public class User {

    private String uid;
    private String email;

    /**
     *
     */
    public User(String uid) {
        this.uid = uid;
    }

    /**
     *
     */
    public void setEmail(String email) {
        this.email = email;
    }

    /**
     *
     */
    public String getUID() {
        return uid;
    }

    /**
     *
     */
    public String getEmail() {
        return email;
    }
}
