package com.github.marschall.directorykeystore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;

import org.junit.jupiter.api.Test;

import com.github.marschall.memoryfilesystem.MemoryFileSystemBuilder;

class DirectoryKeystoreTests {

  // FIXME add chain tests

  @Test
  void etcSslCerts() throws GeneralSecurityException, IOException {
    Path etcSslCerts = Paths.get("/etc/ssl/certs");
    assumeTrue(Files.exists(etcSslCerts));

    this.checkKeystoreDirectory(etcSslCerts);
  }

  @Test
  void etcPkiTlsCerts() throws GeneralSecurityException, IOException {
    Path etcPkiTlsCerts = Paths.get("/etc/pki/tls/certs");
    assumeTrue(Files.exists(etcPkiTlsCerts));

    this.checkKeystoreDirectory(etcPkiTlsCerts);
  }

  @Test
  void loadCertificateChain() throws GeneralSecurityException, IOException {
    Path certificateDirectory = Paths.get("src", "test", "resources", "sample-keystore", "certificate-chains");
    KeyStore keyStore = KeyStore.getInstance(DirectoryKeystoreProvider.TYPE);
    keyStore.load(new DirectorLoadStoreParameter(certificateDirectory));

    assertEquals(1, keyStore.size());

    assertFalse(keyStore.containsAlias("empty"));
    assertTrue(keyStore.containsAlias("ca-certificates"));

    assertFalse(keyStore.isCertificateEntry("empty"));
    assertTrue(keyStore.isCertificateEntry("ca-certificates"));

    assertNull(keyStore.getCertificateChain("empty"));
    assertNotNull(keyStore.getCertificateChain("ca-certificates"));

    assertNull(keyStore.getCertificate("empty"));
    assertNotNull(keyStore.getCertificate("ca-certificates"));
  }

  private void checkKeystoreDirectory(Path certificateDirectory) throws GeneralSecurityException, IOException {
    KeyStore keyStore = KeyStore.getInstance(DirectoryKeystoreProvider.TYPE);
    keyStore.load(new DirectorLoadStoreParameter(certificateDirectory));

    assertTrue(keyStore.size() > 0);
    Enumeration<String> aliases = keyStore.aliases();
    assertTrue(aliases.hasMoreElements());
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      assertTrue(keyStore.containsAlias(alias));
      assertTrue(keyStore.isCertificateEntry(alias));

      Date creationDate = keyStore.getCreationDate(alias);
      assertNotNull(creationDate);
      assertTrue(creationDate.before(new Date()));

      Certificate certificate = keyStore.getCertificate(alias);
      assertNotNull(certificate);

      Certificate[] certificateChain = keyStore.getCertificateChain(alias);
      assertNotNull(certificateChain);
      assertTrue(certificateChain.length > 0);
      if (certificateChain.length > 1) {
        System.out.println(alias + ": " + certificateChain.length);
      }
    }
  }

  @Test
  void loadAFromMemory() throws IOException, GeneralSecurityException {
    try (FileSystem fileSystem = MemoryFileSystemBuilder.newEmpty().build()) {
      Path source = fileSystem.getPath("/source");
      Files.createDirectories(source);

      KeyStore keyStore = KeyStore.getInstance(DirectoryKeystoreProvider.TYPE);
      keyStore.load(new DirectorLoadStoreParameter(source));
    }
  }

  @Test
  void storeToMemory() throws IOException, GeneralSecurityException {
    try (FileSystem fileSystem = MemoryFileSystemBuilder.newEmpty().build()) {
      Path target = fileSystem.getPath("/target");
      Files.createDirectories(target);

      KeyStore keyStore = KeyStore.getInstance(DirectoryKeystoreProvider.TYPE);
      keyStore.load(null);
      keyStore.store(new DirectorLoadStoreParameter(target));
    }
  }

  private static void generateKeysAndCertificate() throws GeneralSecurityException {
    // https://www.pixelstech.net/article/1406724116-Generate-certificate-in-Java----Self-signed-certificate
    // https://www.mayrhofer.eu.org/post/create-x509-certs-in-java/
    // https://bfo.com/blog/2011/03/08/odds_and_ends_creating_a_new_x_509_certificate/
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(null);
    KeyPair generateKeyPair = keyPairGenerator.generateKeyPair();
  }

  @Test
  void getAlias() {
    assertEquals("abc", DirectoryKeystore.getAlias("abc.pem"));
    assertEquals("abc", DirectoryKeystore.getAlias("abc.crt"));
  }

}
