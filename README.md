# Kerberos and GSS API using ApacheDS

A sample Kerberos project using ApacheDS directory service.

## Build the project

Use Apache Maven to build: 

	$ mvn clean package

## Run the Kerberos server

Put path(s) to LDIF files, which should be imported as the program  argument:

	$ java -jar target/kerberos-using-apacheds.jar test.ldif

You can use property  `${hostname}` in the LDIF file and it will be replaced by the canonical server host name:

	dn: uid=HTTP,ou=Users,dc=jboss,dc=org
	objectClass: top
	objectClass: person
	objectClass: inetOrgPerson
	objectClass: krb5principal
	objectClass: krb5kdcentry
	cn: HTTP
	sn: Service
	uid: HTTP
	userPassword: httppwd
	krb5PrincipalName: HTTP/${hostname}@JBOSS.ORG
	krb5KeyVersionNumber: 0 

### Bind to different address

The server binds to `localhost` by default. If you want to change it, set the Java system property `kerberos.bind.address`:

	$ java -Dkerberos.bind.address=192.168.0.1 -jar target/kerberos-using-apacheds.jar test.ldif

## Stop running server

Use "`stop`" command line argument:

	$ java -jar target/kerberos-using-apacheds.jar stop
