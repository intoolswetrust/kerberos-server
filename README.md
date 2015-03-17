# Kerberos server demo - using ApacheDS

A sample Kerberos project using ApacheDS directory service.

## How to get the sources

You should have [git](http://git-scm.com/) installed

	$ git clone git://github.com/kwart/kerberos-using-apacheds.git

or you can download [current sources as a zip file](https://github.com/kwart/kerberos-using-apacheds/archive/master.zip)

## Build the project

You need to have [Maven](http://maven.apache.org/) installed

	$ cd kerberos-using-apacheds
	$ mvn clean package

## Run the Kerberos server

Launch the generated JAR file. You can put LDIF files as the program arguments:

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

### Bind address

The server binds to `localhost` by default. If you want to change it, set the Java system property `kerberos.bind.address`:

	$ java -Dkerberos.bind.address=192.168.0.1 -jar target/kerberos-using-apacheds.jar test.ldif

### krb5.conf

The application generates simple `krb5.conf` file when launched in the current directory. If you want to use another file,
specify the `kerberos.conf.path` system property:

	$ java -Dkerberos.conf.path=/tmp/krb5.conf -jar target/kerberos-using-apacheds.jar test.ldif

### Test the access - user login

Either configure the JBOSS.ORG realm in the `/etc/krb5.conf` or define alternative path using `KRB5_CONFIG` system variable

	$ export KRB5_CONFIG=/tmp/krb5.conf

Authenticate as a sample user from your LDIF file (`test.ldif`)

	$ kinit hnelson@JBOSS.ORG
	Password for hnelson@JBOSS.ORG: secret

## Stop running server

Use `stop` command line argument:

	$ java -jar target/kerberos-using-apacheds.jar stop

## Generate keytab

The project contains a simple Kerberos keytab generator:

	$ java -classpath kerberos-using-apacheds.jar org.jboss.test.kerberos.CreateKeytab
	Kerberos keytab generator
	-------------------------
	Usage:
	java -classpath kerberos-using-apacheds.jar org.jboss.test.kerberos.CreateKeytab <principalName> <passPhrase> [<principalName2> <passPhrase2> ...] <outputKeytabFile>
	
	$ java -classpath kerberos-using-apacheds.jar org.jboss.test.kerberos.CreateKeytab HTTP/localhost@JBOSS.ORG httppwd http.keytab
	Keytab file was created: /home/kwart/kerberos-tests/http.keytab

