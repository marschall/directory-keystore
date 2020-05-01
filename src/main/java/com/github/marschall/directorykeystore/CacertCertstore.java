package com.github.marschall.directorykeystore;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CRL;
import java.security.cert.CRLSelector;
import java.security.cert.CertSelector;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertStoreSpi;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

public final class CacertCertstore extends CertStoreSpi {

  private Collection<? extends Certificate> certificates;

  CacertCertstore(CertStoreParameters parameters) throws InvalidAlgorithmParameterException {
    super(parameters);
    Path cacert = null;

    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    try (InputStream stream = Files.newInputStream(cacert)) {
      this.certificates = factory.generateCertificates(stream);
    }
    // TODO Auto-generated constructor stub
  }

  @Override
  public Collection<? extends Certificate> engineGetCertificates(
          CertSelector selector) throws CertStoreException {
    if (selector == null) {
      return new ArrayList<>(this.certificates);
    }
    List<Certificate> result = new ArrayList<>();
    for (Certificate certificate : this.certificates) {
      if (selector.match(certificate)) {
        result.add(certificate);
      }
    }
    return result;
  }

  @Override
  public Collection<? extends CRL> engineGetCRLs(CRLSelector selector) {
    return Collections.emptySet();
  }

}
