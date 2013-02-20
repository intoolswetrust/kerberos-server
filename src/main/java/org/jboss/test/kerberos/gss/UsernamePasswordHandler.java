/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.test.kerberos.gss;

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