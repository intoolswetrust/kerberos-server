FROM gcr.io/distroless/java:8
MAINTAINER Josef (kwart) Cacek <josef.cacek@gmail.com>

COPY target/kerberos-server.jar /kerberos-server.jar
ENTRYPOINT ["/usr/bin/java", "-jar", "/kerberos-server.jar"]
EXPOSE 389 88
CMD ["-lp", "389", \
     "-kp", "88", \
     "-b", "0.0.0.0" ]
