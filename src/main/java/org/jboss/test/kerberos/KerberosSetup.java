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
package org.jboss.test.kerberos;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.text.StrSubstitutor;
import org.apache.directory.api.ldap.model.constants.SupportedSaslMechanisms;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.server.annotations.CreateKdcServer;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.annotations.SaslMechanism;
import org.apache.directory.server.core.annotations.AnnotationUtils;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreateIndex;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.factory.DSAnnotationProcessor;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.factory.ServerAnnotationProcessor;
import org.apache.directory.server.kerberos.kdc.KdcServer;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.sasl.cramMD5.CramMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.digestMD5.DigestMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.gssapi.GssapiMechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.ntlm.NtlmMechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.plain.PlainMechanismHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Kerberos configuration and control main class.
 * 
 * @author Josef Cacek
 */
//@formatter:off
@CreateDS( 
  name = "JBossDS",
  partitions =
  {
      @CreatePartition(
          name = "jboss",
          suffix = "dc=jboss,dc=org",
          contextEntry = @ContextEntry( 
              entryLdif =
                  "dn: dc=jboss,dc=org\n" +
                  "dc: jboss\n" +
                  "objectClass: top\n" +
                  "objectClass: domain\n\n" ),
          indexes = 
          {
              @CreateIndex( attribute = "objectClass" ),
              @CreateIndex( attribute = "dc" ),
              @CreateIndex( attribute = "ou" )
          })
  },
  additionalInterceptors = { KeyDerivationInterceptor.class })     
@CreateLdapServer (
        transports =
        {
            @CreateTransport( protocol = "LDAP",  port = 10389)
        },
        saslHost="localhost",
        saslPrincipal="ldap/localhost@JBOSS.ORG",
        saslMechanisms =
        {
            @SaslMechanism( name=SupportedSaslMechanisms.PLAIN, implClass=PlainMechanismHandler.class ),
            @SaslMechanism( name=SupportedSaslMechanisms.CRAM_MD5, implClass=CramMd5MechanismHandler.class),
            @SaslMechanism( name= SupportedSaslMechanisms.DIGEST_MD5, implClass=DigestMd5MechanismHandler.class),
            @SaslMechanism( name=SupportedSaslMechanisms.GSSAPI, implClass=GssapiMechanismHandler.class),
            @SaslMechanism( name=SupportedSaslMechanisms.NTLM, implClass=NtlmMechanismHandler.class),
            @SaslMechanism( name=SupportedSaslMechanisms.GSS_SPNEGO, implClass=NtlmMechanismHandler.class)
        })
@CreateKdcServer(primaryRealm = "JBOSS.ORG",
  kdcPrincipal = "krbtgt/JBOSS.ORG@JBOSS.ORG",
  searchBaseDn = "dc=jboss,dc=org",
  transports = 
  { 
      @CreateTransport(protocol = "UDP", port = 6088)
  })
//@formatter:on
public class KerberosSetup {
    private static Logger LOGGER = LoggerFactory.getLogger(KerberosSetup.class);

    private static final int SOCKET_TIMEOUT = 2000; // 2 seconds

    private static final String STOP_CMD = "stop";
    private static final int SERVER_PORT = 10959;

    private DirectoryService directoryService;
    private LdapServer ldapServer;
    private KdcServer kdcServer;
    private final String canonicalHost;
    private final String krb5ConfPath;

    // Constructors ----------------------------------------------------------

    public KerberosSetup() {
        canonicalHost = getCannonicalHost(System.getProperty("kerberos.bind.address", "localhost"));
        krb5ConfPath = System.getProperty("kerberos.conf.path", "krb5.conf");
    }

    // Public methods --------------------------------------------------------

    /**
     * 
     * @param args
     */
    public static void main(String[] args) {
        try {
            if (args.length == 1 && STOP_CMD.equals(args[0])) {
                System.out.println("Sending STOP command to Kerberos controll process.");
                SocketAddress sockaddr = new InetSocketAddress(InetAddress.getLocalHost(), SERVER_PORT);
                // Create an unbound socket
                Socket sock = new Socket();
                sock.connect(sockaddr, SOCKET_TIMEOUT);
                BufferedWriter wr = new BufferedWriter(new OutputStreamWriter(sock.getOutputStream()));
                wr.write(STOP_CMD);
                wr.close();
                sock.close();
            } else {
                System.out.println("Starting Kerberos controll process.");
                KerberosSetup ns = new KerberosSetup();
                ns.startKDC(args);
                ns.waitForStop();
                ns.stopKDC();
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

    }

    // Protected methods -----------------------------------------------------

    protected void waitForStop() throws Exception {
        final ServerSocket srv = new ServerSocket(SERVER_PORT);
        boolean isStop = false;
        do {
            // Wait for connection from client.
            Socket socket = srv.accept();
            System.out.println("Incomming connection.");
            socket.setSoTimeout(SOCKET_TIMEOUT);
            BufferedReader rd = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            try {
                isStop = STOP_CMD.equals(rd.readLine());
            } finally {
                rd.close();
            }
            System.out.println("Stop command: " + isStop);
            socket.close();
        } while (!isStop);
        IOUtils.closeQuietly(srv);
    }

    protected void startKDC(final String[] args) throws Exception {
        directoryService = DSAnnotationProcessor.getDirectoryService();
        LOGGER.info("Initializing KDC server with binding to '{}'", canonicalHost);
        final Map<String, String> map = new HashMap<String, String>();
        map.put("hostname", canonicalHost);
        if (args != null && args.length > 0) {
            for (String ldifFile : args) {

                final String ldifContent = StrSubstitutor.replace(FileUtils.readFileToString(new File(ldifFile), "UTF-8"), map);
                LOGGER.debug(ldifContent);
                final SchemaManager schemaManager = directoryService.getSchemaManager();
                try {
                    for (LdifEntry ldifEntry : new LdifReader(IOUtils.toInputStream(ldifContent))) {
                        directoryService.getAdminSession().add(new DefaultEntry(schemaManager, ldifEntry.getEntry()));
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    throw e;
                }
            }
        }
        LOGGER.info("Generating kerberos configuration file '{}'", krb5ConfPath);
        FileUtils.write(new File(krb5ConfPath),
                StrSubstitutor.replace(IOUtils.toString(getClass().getResourceAsStream("/krb5.conf"), "UTF-8"), map));
        System.out.println("Starting KDC");
        kdcServer = KDCServerAnnotationProcessor.getKdcServer(directoryService, 1024, canonicalHost);
        System.out.println("Starting LDAP server");
        final ManagedCreateLdapServer createLdapServer = new ManagedCreateLdapServer(
                (CreateLdapServer) AnnotationUtils.getInstance(CreateLdapServer.class));
        createLdapServer.setSaslHost(canonicalHost);
        createLdapServer.setSaslPrincipal("ldap/" + canonicalHost + "@JBOSS.ORG");
        fixTransportAddress(createLdapServer, canonicalHost);
        ldapServer = ServerAnnotationProcessor.instantiateLdapServer(createLdapServer, directoryService);
        ldapServer.setSearchBaseDn("dc=jboss,dc=org");
        ldapServer.start();
    }

    protected void stopKDC() throws Exception {
        System.out.println("Stoping LDAP server.");
        ldapServer.stop();
        System.out.println("Stoping Kerberos server.");
        kdcServer.stop();
        System.out.println("Stoping Directory service.");
        directoryService.shutdown();
        System.out.println("Removing Directory service workfiles.");
        FileUtils.deleteDirectory(directoryService.getInstanceLayout().getInstanceDirectory());
    }

    // Private methods -------------------------------------------------------

    /**
     * Returns canonical hostname form of the given host address.
     * 
     * @param host address
     * @return
     */
    private static final String getCannonicalHost(String host) {
        try {
            host = InetAddress.getByName(host).getCanonicalHostName();
        } catch (UnknownHostException e) {
            LOGGER.warn("Unable to get cannonical host name", e);
        }
        return host.toLowerCase(Locale.ENGLISH);
    }

    /**
     * Fixes bind address in the CreateTransport annotation.
     *
     * @param createLdapServer
     */
    private void fixTransportAddress(ManagedCreateLdapServer createLdapServer, String address) {
        final CreateTransport[] createTransports = createLdapServer.transports();
        for (int i = 0; i < createTransports.length; i++) {
            final ManagedCreateTransport mgCreateTransport = new ManagedCreateTransport(createTransports[i]);
            mgCreateTransport.setAddress(address);
            createTransports[i] = mgCreateTransport;
        }
    }
}
