package com.github.marschall.directorykeystore;

import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.junit.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.DomainLoadStoreParameter;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.ProtectionParameter;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class DomainKeystoreTests {

  @Test
  void load() throws GeneralSecurityException, IOException, URISyntaxException {
    KeyStore keyStore = KeyStore.getInstance("DKS");
    URI dksUri = new URI(DomainKeystoreTests.class.getClassLoader().getResource("sample-keystore/dks/sample.dks").toExternalForm() + "#junit");
    Map<String, ProtectionParameter> protectionParams = Collections.emptyMap();
    LoadStoreParameter loadStoreParameter = new DomainLoadStoreParameter(dksUri, protectionParams);
    keyStore.load(loadStoreParameter);

    List<String> aliases = Collections.list(keyStore.aliases());

    assertTrue(keyStore.isCertificateEntry("cert")); // from the directory truststore

    boolean isTravis = System.getenv().containsKey("TRAVIS");
    if (!isTravis) {
      // tavis has a different system truststore
      // system_truststore debian:isrg_root_x1.pem
      assertTrue(keyStore.isCertificateEntry("system_truststore letsencryptisrgx1 [jdk]"), () -> "alias missing from: " + aliases); // from the JDK truststore
      // travis system_truststore debian:digicert_global_root_ca.pem
      assertTrue(keyStore.isCertificateEntry("system_truststore digicertglobalrootca [jdk]"), () -> "alias missing from: " + aliases); // from the JDK truststore
    }
    assertThat(aliases, hasSize(greaterThan(10))); // from the JDK truststore
  }

}
