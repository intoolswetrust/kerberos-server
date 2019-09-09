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

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;

import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class InitSpn {

    private final static Oid KRB5_OID;
    static {
        try {
            KRB5_OID = new Oid("1.2.840.113554.1.2.2");
        } catch (GSSException e) {
            throw new RuntimeException(e);
        }
    }

    private final String spn;

    public InitSpn(String spn) {
        this.spn = spn;
    }

    public String getName() throws IOException, GSSException {
        GSSContext gssContext = null;
        try {
            GSSManager manager = GSSManager.getInstance();
            gssContext = manager.createContext(manager.createName(spn, null), KRB5_OID, null, GSSContext.DEFAULT_LIFETIME);
            byte[] token = new byte[0];
            token = gssContext.initSecContext(token, 0, token.length);
            GSSName srcName = gssContext.getSrcName();
            System.out.println("Source name: " + srcName);
            System.out.println("Target name: " + gssContext.getTargName());
            return srcName.toString();
        } finally {
            if (gssContext != null) {
                try {
                    gssContext.dispose();
                } catch (GSSException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static void main(String[] args) throws LoginException, IOException, GSSException {
        if (args == null || args.length < 2) {
            System.err.println("Usage: InitSpn LogFilePath SPN [SPN...]");
            System.exit(2);
        }
        try (PrintWriter pw = new PrintWriter(new FileOutputStream(args[0], true))) {
            for (int i = 1; i < args.length; i++) {
                try {
                    InitSpn client = new InitSpn(args[i]);
                    String name = client.getName();
                    pw.println(">>> " + name);
                    System.out.println(">>> " + name);
                } catch (Exception e) {
                    e.printStackTrace(pw);
                    e.printStackTrace();
                }
            }
        }
    }
}