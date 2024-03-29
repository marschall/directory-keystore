Directory Keystore [![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.marschall/directory-keystore/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.github.marschall/directory-keystore) [![Javadocs](https://www.javadoc.io/badge/com.github.marschall/directory-keystore.svg)](https://www.javadoc.io/doc/com.github.marschall/directory-keystore)
==================


```xml
<dependency>
    <groupId>com.github.marschall</groupId>
    <artifactId>directory-keystore</artifactId>
    <version>1.1.0</version>
</dependency>
```

A Java keystore that allows you to place certificates in a directory. This is interesting for example in Linux where the system certificates are in `/etc/ssl/certs/` on Ubunut and `/etc/pki/tls/certs` on RHEL.

We read certificates and certificate chains file with the following extensions

* `.pem`
* `.crt`

We read public and private key file extensions

* `.key`

## Usage from Java

### Using LoadStoreParameter

We recommend using the `#load` method that uses a `LoadStoreParameter` instead of the one that uses `InputStream` as you can directly pass a `Path` to a directory.

An instance of the provider can be acquired using

```java
Path etcSslCerts = Paths.get("/etc/ssl/certs");
KeyStore keyStore = KeyStore.getInstance("directory"); // DirectoryKeystoreProvider.TYPE
keyStore.load(new DirectoryLoadStoreParameter(certificateDirectory));
```

### Using InputStream

If you instead want to load the keystore using and `InputStream` you have to use a redirect files that points to the actual location of the folder containing the certificates.

```java
KeyStore keyStore = KeyStore.getInstance("directory"); // DirectoryKeystoreProvider.TYPE
try (InputStream inputStream = Files.newInputStream(Paths.get("conf/keystore.redirect"))) {
  keyStore.load(inputStream);
}
```

## Usage from Configuration Files

In configuration files it is usually not possible to specify a custom `LoadStoreParameter`, instead often only a file can be specified. Unfortunately you can't directly specify the directory in which your certificates are located because on the Java side we would get a `InputStream` on the directory. Instead you have to create a file that contains a string with the directory that contains the certificates.

```
echo "/etc/ssl/certs" > "/home/app/truststore"
```

```
truststoreType="directory"
truststoreFile="/home/app/truststore"
```

## Installation

The provider can be installed in two different ways

1. programmatic installation
1. static installation

### Programmatic Installation

The provider can be installed programmatically using

```java
Security.addProvider(new DirectoryKeystoreProvider());
```

### Static Installation Java 8

The provider can be installed statically in the `java.security` file by adding the provider at the end

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

### Static Installation Java 9+

The provider can be installed statically in the `java.security` file by adding the provider at the end

```
security.provider.N=directory
```

`N` should be the value of the last provider incremented by 1. For OpenJDK 11 on Linux `N` should likely be 13.

This can be done
 * [per JVM installation](https://docs.oracle.com/en/java/javase/11/security/howtoimplaprovider.html#GUID-831AA25F-F702-442D-A2E4-8DA6DEA16F33)
 * [per JVM Instance](https://docs.oracle.com/en/java/javase/11/security/java-authentication-and-authorization-service-jaas-reference-guide.html#GUID-106F4B32-B9A3-4B75-BDBF-29B252BB3F53).
   * by appending to the `java.security` file using `-Djava.security.properties=/path/to/custom.java.security`
   * by replacing to the `java.security` file using `-Djava.security.properties==/path/to/custom.java.security`
   
The provider uses the ServiceLoader mechanism therefore using the `directory` string is enough, there is no need to use the fully qualified class name.

Note that for this to work the provider JAR needs to be in the class path or module path.


## Usage as a JVM Default Truststore

This libray can be used as a JVM default truststore replacing the built-in one. To do this you need to set the `java.security.properties`, `javax.net.ssl.trustStore` and `javax.net.ssl.trustStoreType` system properties

```
-Djava.security.properties=$(pwd)/conf/additional.java.security \
-Djavax.net.ssl.trustStore=$(pwd)/conf/etcsslcerts \
-Djavax.net.ssl.trustStoreType=directory
```

Check out [marschall/directory-keystore-demo](https://github.com/marschall/directory-keystore-demo) for an example.

## Combining with the Java Default Truststore

If you want to combine the default Java truststore with the truststore of your Linux distribution [DKS](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/DomainLoadStoreParameter.html) keystore. You need to create a configuration file similar to the following one:

```
domain system_plus_java {

    keystore system_truststore // the trustore form the Linux distribution
        keystoreType="directory"
        keystoreURI="${user.dir}/conf/etcsslcerts"; // contains the name of the actual folder, for example /etc/ssl/certs

    keystore java_truststore // the JDK default truststore
        keystoreURI="${java.home}/lib/security/cacerts";

};
```

And you can then load the keystore with code similar to this:

```java
KeyStore keyStore = KeyStore.getInstance("DKS");
URI dksUri = new URI(DomainKeystoreTests.class.getClassLoader().getResource("conf/combined.dks").toExternalForm() + "#system_plus_java");
Map<String, ProtectionParameter> protectionParams = Collections.emptyMap();
LoadStoreParameter loadStoreParameter = new DomainLoadStoreParameter(dksUri, protectionParams);
keyStore.load(loadStoreParameter);
```


