package com.github.kwart.kerberos;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

import java.io.File;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang.text.StrSubstitutor;
import org.apache.directory.api.ldap.model.constants.SupportedSaslMechanisms;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.IOUtils;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.interceptor.Interceptor;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.core.partition.impl.avl.AvlPartition;
import org.apache.directory.server.kerberos.KerberosConfig;
import org.apache.directory.server.kerberos.kdc.KdcServer;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.sasl.cramMD5.CramMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.digestMD5.DigestMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.gssapi.GssapiMechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.ntlm.NtlmMechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.plain.PlainMechanismHandler;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.protocol.shared.transport.UdpTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.beust.jcommander.JCommander;

/**
 * The Kerberos server.
 */
public class KerberosServer {

    private static Logger LOGGER = LoggerFactory.getLogger(KerberosServer.class);

    private static final String DEFAULT_LDIF_FILENAME = "default.ldif";

    private final KerberosOptions options;

    private final DirectoryService directoryService;
    private final LdapServer ldapServer;
    private final KdcServer kdcServer;
    private final Map<String, String> replacementMap = new HashMap<>();

    public static void main(String[] args) {
        KerberosOptions opts = new KerberosOptions();
        JCommander jcmd = JCommander.newBuilder().programName("java -jar kerberos-server.jar").addObject(opts).build();
        jcmd.parse(args);

        if (opts.isHelp()) {
            jcmd.usage();
            return;
        }
        try {
            KerberosServer kerberosServer = new KerberosServer(opts);
            kerberosServer.start();
        } catch (Exception e) {
            LOGGER.error("Kerberos Server start failed", e);
            System.exit(1);
        }
    }

    public KerberosServer(KerberosOptions options) throws Exception {
        this.options = requireNonNull(options);
        long startTime = System.currentTimeMillis();
        fillReplacementMap();
        InMemoryDirectoryServiceFactory dsFactory = new InMemoryDirectoryServiceFactory();
        dsFactory.init("ds");

        directoryService = dsFactory.getDirectoryService();
        KeyDerivationInterceptor keyDerivationInterceptor = new KeyDerivationInterceptor();
        keyDerivationInterceptor.init(directoryService);
        directoryService.addLast(keyDerivationInterceptor);
        LOGGER.info("Directory service started in " + (System.currentTimeMillis() - startTime) + "ms");
        directoryService.setAllowAnonymousAccess(options.isAllowAnonymous());
        importLdif(options.getLdifFiles());
        String customPassword = options.getAdminPassword();
        if (customPassword != null) {
            LOGGER.info("Modifying password for the system account uid=admin,ou=system");
            Modification replacePwd = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "userPassword",
                    customPassword);
            Dn adminDn = directoryService.getDnFactory().create("uid=admin,ou=system");
            directoryService.getAdminSession().modify(adminDn, replacePwd);
        }

        ldapServer = new org.apache.directory.server.ldap.LdapServer();
        TcpTransport tcp = new TcpTransport(options.getBindAddress(), options.getLdapPort());
        if (options.getLdapTlsPort() != null) {
            TcpTransport ldapsTcp = new TcpTransport(options.getBindAddress(), options.getLdapTlsPort());
            ldapsTcp.setEnableSSL(true);
            ldapsTcp.setEnabledProtocols(options.getLdapTlsProtocols());
            ldapsTcp.setEnabledCiphers(options.getLdapTlsCipherSuites());
            ldapsTcp.setNeedClientAuth(options.isLdapTlsMutual());
            ldapsTcp.setWantClientAuth(options.isLdapTlsMutual());

            ldapServer.setKeystoreFile(options.getLdapsKeystoreFile());
            ldapServer.setCertificatePassword(options.getLdapsKeystorePassword());
            ldapServer.setTransports(tcp, ldapsTcp);
        } else {
            ldapServer.setTransports(tcp);
        }
        ldapServer.setDirectoryService(directoryService);
        String canonicalhost = replacementMap.get("canonicalhost");
        ldapServer.setSaslHost(canonicalhost);
        ldapServer.setSaslPrincipal("ldap/" + canonicalhost + "@" + options.getKerberosRealm());
        ldapServer.addSaslMechanismHandler(SupportedSaslMechanisms.PLAIN, new PlainMechanismHandler());
        ldapServer.addSaslMechanismHandler(SupportedSaslMechanisms.CRAM_MD5, new CramMd5MechanismHandler());
        ldapServer.addSaslMechanismHandler(SupportedSaslMechanisms.DIGEST_MD5, new DigestMd5MechanismHandler());
        ldapServer.addSaslMechanismHandler(SupportedSaslMechanisms.GSSAPI, new GssapiMechanismHandler());
        ldapServer.addSaslMechanismHandler(SupportedSaslMechanisms.NTLM, new NtlmMechanismHandler());
        ldapServer.addSaslMechanismHandler(SupportedSaslMechanisms.GSS_SPNEGO, new NtlmMechanismHandler());

        kdcServer = new KdcServer();
        kdcServer.setServiceName("KerberosServer");
        kdcServer.setSearchBaseDn(getPartitionName());
        KerberosConfig config = kdcServer.getConfig();
        String realm = options.getKerberosRealm();
        config.setServicePrincipal("krbtgt/" + realm + "@" + realm);
        config.setPrimaryRealm(realm);
        config.setMaximumTicketLifetime(TimeUnit.DAYS.toMillis(1));
        config.setMaximumRenewableLifetime(TimeUnit.DAYS.toMillis(7));

        config.setPaEncTimestampRequired(false);

        kdcServer.addTransports(new UdpTransport(options.getBindAddress(), options.getKerberosPort()),
                new TcpTransport(options.getBindAddress(), options.getKerberosPort()));
        kdcServer.setDirectoryService(directoryService);

        File krb5conf = options.getKrb5conf();
        if (krb5conf != null) {
            if (krb5conf.isDirectory()) {
                krb5conf = new File(krb5conf, "krb5.conf");
            }
            LOGGER.info("Generating kerberos configuration file '{}'", krb5conf.getAbsolutePath());
            String krb5Source = IOUtils.toString(getClass().getResourceAsStream("/krb5.conf"), UTF_8);
            Files.write(krb5conf.toPath(), StrSubstitutor.replace(krb5Source, replacementMap).getBytes(UTF_8));
        }
    }

    private void fillReplacementMap() {
        String host = options.getBindAddress();
        if (KerberosOptions.DEFAULT_BIND_ADDR.equals(host)) {
            host = "127.0.0.1";
        }
        replacementMap.put("host", host);
        replacementMap.put("canonicalhost", getCanonicalHost(host));
        replacementMap.put("realm", options.getKerberosRealm());
    }

    private String getPartitionName() {
        for (Partition partition : directoryService.getPartitions()) {
            String name = partition.getSuffixDn().getName();
            if (!"ou=schema".equals(name)) {
                return name;
            }
        }
        return "ou=schema";
    }

    public void start() throws Exception {
        long startTime = System.currentTimeMillis();
        ldapServer.start();
        kdcServer.start();

        LOGGER.info("You can connect to the server now");
        final String host;
        if (KerberosOptions.DEFAULT_BIND_ADDR.equals(options.getBindAddress())) {
            host = "127.0.0.1";
        } else {
            host = options.getBindAddress();
        }
        String formattedHost = formatPossibleIpv6(host);
        String formattedCanonicalHost = formatPossibleIpv6(getCanonicalHost(host));
        LOGGER.info("Kerberos:  " + formattedHost + ":" + options.getKerberosPort());
        LOGGER.info("LDAP URL:  ldap://" + formattedCanonicalHost + ":" + options.getLdapPort());
        if (options.getLdapTlsPort() != null) {
            LOGGER.info("           ldaps://" + formattedCanonicalHost + ":" + options.getLdapTlsPort());
        }
        LOGGER.info("User DN:   uid=admin,ou=system");
        LOGGER.info("Password:  " + (options.getAdminPassword() != null ? "***" : "secret"));
        LOGGER.info("Servers started in " + (System.currentTimeMillis() - startTime) + "ms");

    }

    public void stop() throws Exception {
        kdcServer.stop();
        ldapServer.stop();
        directoryService.shutdown();
    }

    /**
     * Imports given LDIF file to the directory using given directory service and schema manager.
     */
    private void importLdif(List<Path> ldifFiles) throws Exception {
        if (ldifFiles == null || ldifFiles.isEmpty()) {
            LOGGER.info("Importing default data\n");
            importLdif(IOUtils.toString(getClass().getResourceAsStream("/" + DEFAULT_LDIF_FILENAME), UTF_8));
        } else {
            for (Path ldifFile : ldifFiles) {
                LOGGER.info("Importing " + ldifFile + "\n");
                importLdif(new String(Files.readAllBytes(ldifFile), UTF_8));
            }
        }
    }

    private void importLdif(String ldifSource) throws Exception {
        String ldifContent = StrSubstitutor.replace(ldifSource, replacementMap);
        SchemaManager schemaManager = directoryService.getSchemaManager();
        try (LdifReader ldifReader = new LdifReader(new StringReader(ldifContent))) {
            for (LdifEntry ldifEntry : ldifReader) {
                checkPartition(ldifEntry);
                System.out.print(ldifEntry.toString());
                directoryService.getAdminSession().add(new DefaultEntry(schemaManager, ldifEntry.getEntry()));
            }
        }
    }

    private void checkPartition(LdifEntry ldifEntry) throws Exception {
        Dn dn = ldifEntry.getDn();
        Dn parent = dn.getParent();
        try {
            directoryService.getAdminSession().exists(parent);
        } catch (Exception e) {
            LOGGER.info("Creating new partition for DN=" + dn + "\n");
            AvlPartition partition = new AvlPartition(directoryService.getSchemaManager());
            partition.setId(dn.getName());
            partition.setSuffixDn(dn);
            directoryService.addPartition(partition);
        }
    }

    private String formatPossibleIpv6(String host) {
        return (host != null && host.contains(":")) ? "[" + host + "]" : host;
    }

    private static final String getCanonicalHost(String host) {
        try {
            host = InetAddress.getByName(host).getCanonicalHostName();
        } catch (UnknownHostException e) {
            LOGGER.warn("Unable to get cannonical host name", e);
        }
        return host.toLowerCase(Locale.ENGLISH);
    }
}
