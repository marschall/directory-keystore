package com.github.marschall.directorykeystore;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.Security;

import org.junit.jupiter.api.Test;

class ProviderInstallationTests {

  @Test
  void getProvider() {
    assertNotNull(Security.getProvider(DirectoryKeystoreProvider.NAME));
  }

}
