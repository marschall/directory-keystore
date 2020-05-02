package com.github.marschall.directorykeystore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;

import org.junit.jupiter.api.Test;

class DirectoryKeystoreTests {

  @Test
  void etcSslCerts() throws GeneralSecurityException, IOException {
    Path etcSslCerts = Paths.get("/etc/ssl/certs");
    assumeTrue(Files.exists(etcSslCerts));

    KeyStore keyStore = KeyStore.getInstance(DirectoryKeystoreProvider.TYPE);
    keyStore.load(new DirectorLoadStoreParameter(etcSslCerts));

    Enumeration<String> aliases = keyStore.aliases();
    assertTrue(aliases.hasMoreElements());
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      assertTrue(keyStore.containsAlias(alias));

      Date creationDate = keyStore.getCreationDate(alias);
      assertNotNull(creationDate);
      assertTrue(creationDate.before(new Date()));

      Certificate certificate = keyStore.getCertificate(alias);
      assertNotNull(certificate);
    }
  }

  @Test
  void getAlias() {
    assertEquals("abc", DirectoryKeystore.getAlias("abc.pem"));
    assertEquals("abc", DirectoryKeystore.getAlias("abc.crt"));
  }

}
