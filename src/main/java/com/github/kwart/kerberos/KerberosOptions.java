package com.github.kwart.kerberos;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.converters.FileConverter;
import com.beust.jcommander.converters.PathConverter;

/**
 * Kerberos options.
 */
public class KerberosOptions {

    public static final String DEFAULT_BIND_ADDR = "0.0.0.0";
    public static final int DEFAULT_LDAP_PORT = 10389;

    public static final int DEFAULT_KERBEROS_PORT = 6088;
    public static final String DEFAULT_KERBEROS_REALM = "KERBEROS.EXAMPLE";

    @Parameter(description = "[LDIFs to import]", converter = PathConverter.class)
    private List<Path> ldifFiles = new ArrayList<>();

    @Parameter(names = { "--help", "-h" }, description = "shows this help and exits", help = true)
    private boolean help;

    @Parameter(names = { "--allow-anonymous", "-a" }, description = "allows anonymous bind to the LDAP server")
    private boolean allowAnonymous;

    @Parameter(names = { "--admin-password",
            "-ap" }, description = "changes password for account 'uid=admin,ou=system' (default password is 'secret')")
    private String adminPassword;

    @Parameter(names = { "--ldap-port",
            "-lp" }, description = "takes [portNumber] as a parameter and binds the LDAP server on that port")
    private int ldapPort = DEFAULT_LDAP_PORT;

    @Parameter(names = { "--bind",
            "-b" }, description = "takes [bindAddress] as a parameter and binds the servers on the address")
    private String bindAddress = DEFAULT_BIND_ADDR;

    @Parameter(names = { "--ldap-tls-port",
            "-ltp" }, description = "adds TLS transport layer (i.e. 'ldaps' protocol). It takes [portNumber] as a parameter and binds the LDAPs server on the port")
    private Integer ldapTlsPort = null;

    @Parameter(names = { "--ldap-tls-mutual", "-ltm" }, description = "enables TLS mutual authetntication for ldaps protocol")
    private boolean ldapTlsMutual;

    @Parameter(names = { "--ldap-tls-protocol",
            "-ltl" }, description = "takes [protocolName] as argument and enables it for 'ldaps'. Can be used multiple times.")
    private List<String> ldapTlsProtocols;

    @Parameter(names = { "--ldap-tls-ciphersuite",
            "-ltc" }, description = "takes [cipherSuite] as argument and enables it for 'ldaps'. Can be used multiple times.")
    private List<String> ldapTlsCipherSuites;

    @Parameter(names = { "--ldaps-keystore-file",
            "-lkf" }, description = "takes keystore [filePath] as argument. The keystore should contain privateKey to be used by LDAPs")
    private String ldapsKeystoreFile;

    @Parameter(names = { "--ldaps-keystore-password", "-lkp" }, description = "takes LDAPs keystore [password] as argument")
    private String ldapsKeystorePassword;

    @Parameter(names = { "--kerberos-port", "-kp" }, description = "takes KDC [port] number as argument")
    private int kerberosPort = DEFAULT_KERBEROS_PORT;

    @Parameter(names = { "--kerberos-realm", "-kr" }, description = "takes the Kerberos [REALM.NAME] as argument")
    private String kerberosRealm = DEFAULT_KERBEROS_REALM;

    @Parameter(names = { "--disable-replay-cache", "-drc" }, description = "disables replay cache in KDC")
    private boolean disableReplayCache;

    @Parameter(names = { "--generate-krb5-conf", "-c" }, description = "takes [krb5.conf] file path as argument and generates the content during KDC start",
            converter = FileConverter.class)
    private File krb5conf;

    public boolean isHelp() {
        return help;
    }

    public void setHelp(boolean help) {
        this.help = help;
    }

    public boolean isAllowAnonymous() {
        return allowAnonymous;
    }

    public void setAllowAnonymous(boolean allowAnonymous) {
        this.allowAnonymous = allowAnonymous;
    }

    public String getAdminPassword() {
        return adminPassword;
    }

    public void setAdminPassword(String adminPassword) {
        this.adminPassword = adminPassword;
    }

    public int getLdapPort() {
        return ldapPort;
    }

    public void setLdapPort(int ldapPort) {
        this.ldapPort = ldapPort;
    }

    public String getBindAddress() {
        return bindAddress;
    }

    public void setBindAddress(String bindAddress) {
        this.bindAddress = bindAddress;
    }

    public Integer getLdapTlsPort() {
        return ldapTlsPort;
    }

    public void setLdapTlsPort(Integer ldapTlsPort) {
        this.ldapTlsPort = ldapTlsPort;
    }

    public boolean isLdapTlsMutual() {
        return ldapTlsMutual;
    }

    public void setLdapTlsMutual(boolean ldapTlsMutual) {
        this.ldapTlsMutual = ldapTlsMutual;
    }

    public List<String> getLdapTlsProtocols() {
        return ldapTlsProtocols;
    }

    public void setLdapTlsProtocols(List<String> ldapTlsProtocols) {
        this.ldapTlsProtocols = ldapTlsProtocols;
    }

    public List<String> getLdapTlsCipherSuites() {
        return ldapTlsCipherSuites;
    }

    public void setLdapTlsCipherSuites(List<String> ldapTlsCipherSuites) {
        this.ldapTlsCipherSuites = ldapTlsCipherSuites;
    }

    public String getLdapsKeystoreFile() {
        return ldapsKeystoreFile;
    }

    public void setLdapsKeystoreFile(String ldapsKeystoreFile) {
        this.ldapsKeystoreFile = ldapsKeystoreFile;
    }

    public String getLdapsKeystorePassword() {
        return ldapsKeystorePassword;
    }

    public void setLdapsKeystorePassword(String ldapsKeystorePassword) {
        this.ldapsKeystorePassword = ldapsKeystorePassword;
    }

    public int getKerberosPort() {
        return kerberosPort;
    }

    public void setKerberosPort(int kerberosPort) {
        this.kerberosPort = kerberosPort;
    }

    public String getKerberosRealm() {
        return kerberosRealm;
    }

    public void setKerberosRealm(String kerberosRealm) {
        this.kerberosRealm = kerberosRealm;
    }

    public List<Path> getLdifFiles() {
        return ldifFiles;
    }

    public boolean isDisableReplayCache() {
        return disableReplayCache;
    }

    public void setDisableReplayCache(boolean disableReplayCache) {
        this.disableReplayCache = disableReplayCache;
    }

    public File getKrb5conf() {
        return krb5conf;
    }

    public void setKrb5conf(File krb5conf) {
        this.krb5conf = krb5conf;
    }

    public void setLdifFiles(List<Path> ldifFiles) {
        this.ldifFiles = ldifFiles;
    }

}
