FROM adoptopenjdk/openjdk8:alpine
MAINTAINER Josef (kwart) Cacek <josef.cacek@gmail.com>

RUN apk add -u -U krb5 bash

COPY target/kerberos-server.jar /kerberos-server.jar
ENTRYPOINT ["java", "-jar", "/kerberos-server.jar"]
EXPOSE 389 88
CMD ["-lp", "389", \
     "-kp", "88", \
     "-b", "0.0.0.0" ]
