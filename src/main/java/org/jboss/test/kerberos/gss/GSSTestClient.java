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

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AccountExpiredException;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.CredentialExpiredException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;

/**
 * A client for {@link GSSTestServer}.
 * 
 * @author Josef Cacek
 */
public class GSSTestClient {

    private final static Oid KRB5_OID;
    static {
        try {
            KRB5_OID = new Oid("1.2.840.113554.1.2.2");
        } catch (GSSException e) {
            throw new RuntimeException(e);
        }
    }

    private final String host;
    private final int port;
    private final String spn;

    // Constructors ----------------------------------------------------------

    /**
     * Create a new GSSTestClient.
     * 
     * @param serverHost
     * @param serverPort
     * @param spn Service Principal Name
     */
    public GSSTestClient(String serverHost, int serverPort, String spn) {
        this.host = serverHost;
        this.port = serverPort;
        this.spn = spn;
    }

    // Public methods --------------------------------------------------------

    /**
     * Retrieves the name of calling identity (based on given gssCredential) retrieved from {@link GSSTestServer}.
     * 
     * @param gssCredential
     * @return
     * @throws IOException
     * @throws GSSException
     */
    public String getName(final GSSCredential gssCredential) throws IOException, GSSException {
        // Create an unbound socket
        System.out.println("GSSCredential used:\n" + gssCredential);
        final Socket socket = new Socket();
        GSSContext gssContext = null;
        try {
            socket.connect(new InetSocketAddress(host, port), GSSTestServer.SOCKET_TIMEOUT);
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            System.out.println("Sending NAME command.");
            dos.writeInt(GSSTestServer.CMD_NAME);
            dos.flush();

            GSSManager manager = GSSManager.getInstance();
            gssContext = manager.createContext(manager.createName(spn, null), KRB5_OID, gssCredential,
                    GSSContext.DEFAULT_LIFETIME);

            //            gssContext.requestCredDeleg(true);
            gssContext.requestMutualAuth(true);
            gssContext.requestConf(true);
            gssContext.requestInteg(true);

            byte[] token = new byte[0];
            while (!gssContext.isEstablished()) {
                token = gssContext.initSecContext(token, 0, token.length);
                if (token != null) {
                    dos.writeInt(token.length);
                    dos.write(token);
                    dos.flush();
                }
                if (!gssContext.isEstablished()) {
                    token = new byte[dis.readInt()];
                    dis.readFully(token);
                }
            }

            token = new byte[dis.readInt()];
            dis.readFully(token);
            MessageProp msgProp = new MessageProp(false);
            final byte[] nameBytes = gssContext.unwrap(token, 0, token.length, msgProp);
            return new String(nameBytes, GSSTestServer.CHAR_ENC);
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            if (gssContext != null) {
                try {
                    gssContext.dispose();
                } catch (GSSException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static void main(String[] args) throws LoginException, MalformedURLException {
        Krb5LoginConfiguration krb5Config = new Krb5LoginConfiguration(Configuration.getConfiguration());
        Configuration.setConfiguration(krb5Config);
        LoginContext lc = null;
        try {
            lc = new LoginContext(krb5Config.getName(), new CallbackHandler() {
                
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    throw new UnsupportedCallbackException(callbacks[0]);
                }
            });
        } catch (LoginException le) {
            System.err.println("Cannot create LoginContext. "
                + le.getMessage());
            System.exit(-1);
        } catch (SecurityException se) {
            System.err .println("Cannot create LoginContext. "
                + se.getMessage());
            System.exit(-1);
        }
                lc.login();

        // push the subject into the current ACC
        try {
            Subject.doAsPrivileged(lc.getSubject(),
                                   new  PrivilegedExceptionAction<Void>() {

                                    @Override
                                    public Void run() throws IOException, GSSException {
                                        GSSTestClient client = new GSSTestClient("localhost", GSSTestServer.PORT, GSSTestServer.PRINCIPAL);
                                        System.out.println(">>> "+client.getName(null));
                                        return null;
                                    }
                                },
                                   null);
        } catch (java.security.PrivilegedActionException pae) {
            pae.printStackTrace();
        }

    }
}