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

    assertTrue(keyStore.isCertificateEntry("cert")); // from the directory truststore

    List<String> aliases = Collections.list(keyStore.aliases());
    assertThat(aliases, hasSize(greaterThan(10))); // from the JDK truststore
  }

}
