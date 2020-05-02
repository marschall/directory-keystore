Directory Keystore
==================

A Java keystore that allows you to place certificates in a directory. This is interesting for example in Linux where the system certificates are in `/etc/ssl/certs/` on Ubunut and ´/etc/pki/tls/certs´ on RHEL.

## Usage

An instance of the provider can be acquired using

```java
Path etcSslCerts = Paths.get("/etc/ssl/certs");
KeyStore keyStore = KeyStore.getInstance("directory"); // DirectoryKeystoreProvider.TYPE
keyStore.load(new DirectorLoadStoreParameter(certificateDirectory));
```

## Configuration

The provider can be configured in two different ways

1. programmatic configuration
1. static configuration

### Programmatic Configuration

The provider can be registered programmatically using

```java
Security.addProvider(new DirectoryKeystoreProvider());
```

### Static Configuration Java 8

The provider can be configured statically in the `java.security` file by adding the provider at the end

```
security.provider.N=com.github.marschall.directorykeystore.DirectoryKeystoreProvider
```

`N` should be the value of the last provider incremented by 1. For Oracle/OpenJDK 8 on Linux `N` should likely be 10.

This can be done
 * [per JVM installation](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/HowToImplAProvider.html#Configuring)
 * [per JVM Instance](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/HowToImplAProvider.html#AppA)
   * by appending to the `java.security` file using `-Djava.security.properties=/path/to/custom.java.security`
   * by replacing to the `java.security` file using `-Djava.security.properties==/path/to/custom.java.security`

Note that for this to work the provider JAR needs to be in the class path or extension folder.

### Static Configuration Java 9+

The provider can be configured statically in the `java.security` file by adding the provider at the end

```
security.provider.N=directory
```

`N` should be the value of the last provider incremented by 1. For Oracle/OpenJDK 9 on Linux `N` should likely be 13.

This can be done
 * [per JVM installation](https://docs.oracle.com/en/java/javase/11/security/howtoimplaprovider.html#GUID-831AA25F-F702-442D-A2E4-8DA6DEA16F33)
 * [per JVM Instance](https://docs.oracle.com/en/java/javase/11/security/java-authentication-and-authorization-service-jaas-reference-guide.html#GUID-106F4B32-B9A3-4B75-BDBF-29B252BB3F53).
   * by appending to the `java.security` file using `-Djava.security.properties=/path/to/custom.java.security`
   * by replacing to the `java.security` file using `-Djava.security.properties==/path/to/custom.java.security`
   
The provider uses the ServiceLoader mechanism therefore using the `directory` string is enough, there is no need to use the fully qualified class name.

Note that for this to work the provider JAR needs to be in the class path or module path.


