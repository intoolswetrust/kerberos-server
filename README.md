# Simple Kerberos server

A simple Kerberos (+LDAP) server on top of the ApacheDS directory service. Just for testing and playing with the protocols.

## Run the Kerberos server

Launch the generated JAR file. You can put LDIF files as the program arguments:

	$ java -jar target/kerberos-server.jar

## LDIF(s)

The program can take LDIF files as arguments. The following placeholders are supported in the ldif:
* `${realm}` - Kerberos realm name
* `${host}` - bind address (127.0.0.1 is used when wildcard address is used;
* `${canonicalhost}` canonical version of the host.

## Generate keytab

The project contains a simple Kerberos keytab generator:

	$ java -classpath target/kerberos-server.jar com.github.kwart.kerberos.CreateKeytab
	Kerberos keytab generator
	-------------------------
	Usage:
	java -classpath target/kerberos-server.jar com.github.kwart.kerberos.CreateKeytab <principalName> <passPhrase> [<principalName2> <passPhrase2> ...] <outputKeytabFile>
	
	$ java -classpath target/kerberos-server.jar com.github.kwart.kerberos.CreateKeytab HTTP/localhost@JBOSS.ORG httppwd http.keytab
	Keytab file was created: /home/kwart/kerberos-tests/http.keytab

