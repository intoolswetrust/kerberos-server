package com.github.kwart.kerberos;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.junit.Test;

public class KerberosServerTest {

    @Test
    public void test() throws Exception {
        Set<Thread> expectedThreads = Thread.getAllStackTraces().keySet();
        KerberosOptions ko = new KerberosOptions();
        String adminPassword = "test";
        ko.setAdminPassword(adminPassword);
        ko.setLdapPort(5701);
        ko.setLdapTlsPort(5702);
        ko.setKerberosPort(5703);
        KerberosServer ks = new KerberosServer(ko);
        ks.start();
        ldapSearch(adminPassword);
        assertThrows(AuthenticationException.class, () -> ldapSearch("secret"));
        ks.stop();
        assertTrueEventually("stacktraces don't match",
                () -> assertEquals(expectedThreads, Thread.getAllStackTraces().keySet()), 60);
    }

    private boolean ldapSearch(String adminPassword) throws Exception {
        Properties env = new Properties();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.PROVIDER_URL, "ldap://127.0.0.1:5701");
        env.put(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        env.put(Context.SECURITY_CREDENTIALS, adminPassword);
        LdapContext ctx = new InitialLdapContext(env, null);
        boolean result = false;
        try {
            final SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            final String baseDN = "dc=kerberos,dc=example";
            NamingEnumeration<?> namingEnum = ctx.search(baseDN, "(uid={0})", new Object[] { "jduke" }, searchControls);
            try {
                result = namingEnum.hasMore();
            } finally {
                namingEnum.close();
            }
        } finally {
            ctx.close();
        }
        return result;
    }

    public static void assertTrueEventually(String message, AssertTask task, long timeoutSeconds) throws Exception {
        AssertionError error = null;
        // we are going to check five times a second
        int sleepMillis = 200;
        long iterations = timeoutSeconds * 5;
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(timeoutSeconds);
        for (int i = 0; i < iterations && System.currentTimeMillis() < deadline; i++) {
            try {
                task.run();
                return;
            } catch (AssertionError e) {
                error = e;
            }
            sleepMillis(sleepMillis);
        }
        if (error != null) {
            throw error;
        }
        fail("assertTrueEventually() failed without AssertionError! " + message);
    }

    public static void sleepMillis(int millis) {
        try {
            TimeUnit.MILLISECONDS.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public interface AssertTask {
        void run() throws Exception;
    }

}
