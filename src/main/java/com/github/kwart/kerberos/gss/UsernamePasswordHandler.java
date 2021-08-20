package com.github.kwart.kerberos.gss;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * A simple implementation of CallbackHandler that sets a username and password in the handle(Callback[]) method to that passed
 * in to the constructor. This is suitable for environments that need non-interactive JAAS logins.
 *
 * @see javax.security.auth.callback.CallbackHandler
 * @see #handle(Callback[])
 * @author Josef Cacek
 */

public class UsernamePasswordHandler implements CallbackHandler {
    private transient String username;
    private transient char[] password;

    /**
     * Initialize the UsernamePasswordHandler with the username and password to use.
     */
    public UsernamePasswordHandler(String username, char[] password) {
        this.username = username;
        this.password = password;
    }

    /**
     * Sets any NameCallback name property to the instance username, sets any PasswordCallback password property to the
     * instance, and any password.
     *
     * @exception UnsupportedCallbackException, thrown if any callback of type other than NameCallback or PasswordCallback are
     *            seen.
     */
    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            Callback c = callbacks[i];
            if (c instanceof NameCallback) {
                final NameCallback nc = (NameCallback) c;
                nc.setName(username);
            } else if (c instanceof PasswordCallback) {
                final PasswordCallback pc = (PasswordCallback) c;
                pc.setPassword(password);
            } else {
                throw new UnsupportedCallbackException(c);
            }
        }
    }
}