package com.github.kwart.kerberos;

/**
 * Class for holding information about principal and passphrase for keytab
 *
 * @author olukas
 */
public class KeytabPrincipalPassphrase {

    private final String principalName;
    private final String passPhrase;

    public KeytabPrincipalPassphrase(String principalName, String passPhrase) {
        this.principalName = principalName;
        this.passPhrase = passPhrase;
    }

    public String getPrincipalName() {
        return principalName;
    }

    public String getPassPhrase() {
        return passPhrase;
    }

}
