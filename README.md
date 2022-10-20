# Simple Kerberos server

A simple Kerberos (+LDAP) server on top of the ApacheDS directory service. Just for testing and playing with the protocols.

## Run the Kerberos server

Launch the generated JAR file. You can put LDIF files as the program arguments:

```
Usage: java -jar kerberos-server.jar [options] [LDIFs to import]
  Options:
    --admin-password, -ap
      changes password for account 'uid=admin,ou=system' (default password is 
      'secret') 
    --allow-anonymous, -a
      allows anonymous bind to the LDAP server
      Default: false
    --bind, -b
      takes [bindAddress] as a parameter and binds the servers on the address
      Default: 0.0.0.0
    --disable-replay-cache, -drc
      disables replay cache in KDC
      Default: false
    --generate-krb5-conf, -c
      takes [krb5.conf] file path as argument and generates the content during 
      KDC start
    --help, -h
      shows this help and exits
    --kerberos-port, -kp
      takes KDC [port] number as argument
      Default: 6088
    --kerberos-realm, -kr
      takes the Kerberos [REALM.NAME] as argument
      Default: KERBEROS.EXAMPLE
    --ldap-port, -lp
      takes [portNumber] as a parameter and binds the LDAP server on that port
      Default: 10389
    --ldap-tls-ciphersuite, -ltc
      takes [cipherSuite] as argument and enables it for 'ldaps'. Can be used 
      multiple times.
    --ldap-tls-mutual, -ltm
      enables TLS mutual authetntication for ldaps protocol
      Default: false
    --ldap-tls-port, -ltp
      adds TLS transport layer (i.e. 'ldaps' protocol). It takes [portNumber] 
      as a parameter and binds the LDAPs server on the port
    --ldap-tls-protocol, -ltl
      takes [protocolName] as argument and enables it for 'ldaps'. Can be used 
      multiple times.
    --ldaps-keystore-file, -lkf
      takes keystore [filePath] as argument. The keystore should contain 
      privateKey to be used by LDAPs
    --ldaps-keystore-password, -lkp
      takes LDAPs keystore [password] as argument
```

## LDIF(s)

The program can take LDIF files as arguments. The following placeholders are supported in the ldif:
* `${realm}` - Kerberos realm name
* `${host}` - bind address (127.0.0.1 is used when wildcard address is used;
* `${canonicalhost}` canonical version of the host.

If no LDIF file argument is provided the default LDIF
([`src/main/resources/default.ldif`](src/main/resources/default.ldif)) is used.

## Generate keytab

The project contains a simple Kerberos keytab generator:

	$ java -classpath target/kerberos-server.jar com.github.kwart.kerberos.CreateKeytab
	Kerberos keytab generator
	-------------------------
	Usage:
	java -classpath target/kerberos-server.jar com.github.kwart.kerberos.CreateKeytab <principalName> <passPhrase> [<principalName2> <passPhrase2> ...] <outputKeytabFile>
	
	$ java -classpath target/kerberos-server.jar com.github.kwart.kerberos.CreateKeytab HTTP/localhost@KERBEROS.EXAMPLE httppwd http.keytab

	$ java -classpath target/kerberos-server.jar com.github.kwart.kerberos.CreateKeytab remote/localhost@KERBEROS.EXAMPLE remotepwd remote.keytab

	Keytab file was created: /home/kwart/kerberos-tests/http.keytab

