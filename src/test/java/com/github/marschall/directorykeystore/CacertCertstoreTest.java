package com.github.marschall.directorykeystore;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.util.Collection;

import org.junit.jupiter.api.Test;

class CacertCertstoreTest {

  @Test
  void etcSslCerts() throws GeneralSecurityException {
    Path etcSslCerts = Paths.get("/etc/ssl/certs");
    assumeTrue(Files.exists(etcSslCerts));

    CertStore certStore = CertStore.getInstance(DirectoryKeystoreProvider.TYPE, new DirectoryCertStoreParameters(etcSslCerts));

    Collection<? extends Certificate> certificates = certStore.getCertificates(null);

    assertFalse(certificates.isEmpty());
  }

  static final class AllCertificates implements CertSelector {

    @Override
    public boolean match(Certificate cert) {
      return true;
    }

    @Override
    public Object clone() {
      try {
        return super.clone();
      } catch (CloneNotSupportedException e) {
        // Cannot happen
        throw new InternalError("clone not supported", e);
      }
    }
  }

}
