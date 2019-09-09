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
import java.net.Socket;

import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;

/**
 * A client for {@link NoJaasGssTestServer}.
 * 
 * @author Josef Cacek
 */
public class NoJaasGssTestClient {

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
    public NoJaasGssTestClient(String serverHost, int serverPort, String spn) {
        this.host = serverHost;
        this.port = serverPort;
        this.spn = spn;
    }


    public String getName() throws IOException, GSSException {
        final Socket socket = new Socket();
        GSSContext gssContext = null;
        try {
            socket.connect(new InetSocketAddress(host, port), NoJaasGssTestServer.SOCKET_TIMEOUT);
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            System.out.println("Sending NAME command.");
            dos.writeInt(NoJaasGssTestServer.CMD_NAME);
            dos.flush();

            GSSManager manager = GSSManager.getInstance();
            gssContext = manager.createContext(manager.createName(spn, null), KRB5_OID, null,
                    GSSContext.DEFAULT_LIFETIME);

            gssContext.requestMutualAuth(false);
            gssContext.requestConf(false);
            gssContext.requestInteg(false);

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
            return new String(nameBytes, NoJaasGssTestServer.CHAR_ENC);
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

    public static void main(String[] args) throws LoginException, IOException, GSSException {
        NoJaasGssTestClient client = new NoJaasGssTestClient("localhost", NoJaasGssTestServer.PORT, args[0]);
        System.out.println(">>> "+client.getName());
    }
}