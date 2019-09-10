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
import java.io.EOFException;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

import org.apache.commons.io.IOUtils;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.MessageProp;

/**
 * A sample server application for testing Kerberos identity propagation.
 * 
 * @author Josef Cacek
 */
public class NoJaasGssTestServer {

    public static final String PROPERTY_PORT = "gsstestserver.port";
    public static final int PORT = Integer.getInteger(PROPERTY_PORT, 10961);

    public static final String CHAR_ENC = "UTF-8";
    public static final int CMD_NOOP = 0;
    public static final int CMD_NAME = 1;
    public static final int CMD_STOP = 2;

    public static final int SOCKET_TIMEOUT = 30 * 1000; // 30s

    private final PrintStream ps;

    public NoJaasGssTestServer(PrintStream ps) {
        this.ps = ps;
    }

    // Public methods --------------------------------------------------------

    /**
     * The Main.
     * 
     * @param args
     */
    public static void main(String[] args) {
        PrintStream ps = System.out;
        try {
            if (args != null && args.length > 0) {
                String param = args[0];
                if ("stop".equals(param)) {
                    NoJaasGssTestServer.stop();
                    return;
                }
                ps = new PrintStream(param, "UTF-8");
            }
            final NoJaasGssTestServer gssTestServer = new NoJaasGssTestServer(ps);
            gssTestServer.start();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void start() {
        final GSSManager gssManager = GSSManager.getInstance();
        ServerSocket serverSocket = null;
        try {
            serverSocket = new ServerSocket(PORT);
            ps.println("Server started on port " + PORT);
            int command = CMD_NOOP;
            do {
                Socket socket = null;
                GSSContext gssContext = null;
                try {
                    ps.println("Waiting for client connection");
                    socket = serverSocket.accept();
                    ps.println("Client connected");
                    gssContext = gssManager.createContext((GSSCredential) null);
                    final DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                    final DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

                    command = dataInputStream.readInt();
                    ps.println("Command code: " + command);
                    if (command == CMD_NAME) {
                        while (!gssContext.isEstablished()) {
                            final byte[] inToken = new byte[dataInputStream.readInt()];
                            dataInputStream.readFully(inToken);
                            final byte[] outToken = gssContext.acceptSecContext(inToken, 0, inToken.length);

                            if (outToken != null) {
                                dataOutputStream.writeInt(outToken.length);
                                dataOutputStream.write(outToken);
                                dataOutputStream.flush();
                            }
                        }
                        final String clientName = gssContext.getSrcName().toString();
                        ps.println("Context Established with Client " + clientName);

                        // encrypt
                        final MessageProp msgProp = new MessageProp(true);
                        final byte[] clientNameBytes = clientName.getBytes(CHAR_ENC);
                        final byte[] outToken = gssContext.wrap(clientNameBytes, 0, clientNameBytes.length, msgProp);

                        dataOutputStream.writeInt(outToken.length);
                        dataOutputStream.write(outToken);
                        dataOutputStream.flush();
                        ps.println("Client name was returned as the token value.");
                    }
                } catch (EOFException e) {
                    ps.println("Client didn't send a correct message.");
                } catch (IOException e) {
                    e.printStackTrace(ps);
                } catch (GSSException e) {
                    e.printStackTrace(ps);
                } finally {
                    if (gssContext != null) {
                        try {
                            gssContext.dispose();
                        } catch (GSSException e) {
                            e.printStackTrace(ps);
                        }
                    }
                    if (socket != null) {
                        try {
                            socket.close();
                        } catch (IOException e) {
                            e.printStackTrace(ps);
                        }
                    }

                }
            } while (command != CMD_STOP);
            ps.println("Stop command received.");
        } catch (IOException e) {
            e.printStackTrace(ps);
        } finally {
            IOUtils.closeQuietly(serverSocket);
        }
    }

    /**
     * Sends STOP ({@link #CMD_STOP}) command to a running server.
     */
    private static void stop() {
        System.out.println("Sending STOP command GSSTestServer.");
        // Create an unbound socket
        final Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(InetAddress.getLocalHost(), PORT), SOCKET_TIMEOUT);
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            dos.writeInt(CMD_STOP);
            dos.flush();
            System.out.println("STOP command sent.");
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}