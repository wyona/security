package org.wyona.security.core;

import org.wyona.security.core.api.AccessManagementException;

public class ExpiredIdentityException extends AccessManagementException {
    private static final long serialVersionUID = 1L;

    public ExpiredIdentityException() {
        super();
    }

    public ExpiredIdentityException(Throwable t) {
        super(t);
    }

    public ExpiredIdentityException(String s) {
        super(s);
    }

    public ExpiredIdentityException(String s, Throwable t) {
        super(s, t);
    }
}
