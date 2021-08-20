package com.github.kwart.kerberos.gss;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

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

}