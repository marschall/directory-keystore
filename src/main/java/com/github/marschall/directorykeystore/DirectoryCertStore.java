package com.github.marschall.directorykeystore;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class DirectoryCertStore extends CertStoreSpi {

  private Path dirctory;

  DirectoryCertStore(CertStoreParameters parameters) throws InvalidAlgorithmParameterException {
    super(parameters);
    if (!(parameters instanceof DirectoryCertStoreParameters)) {
      throw new InvalidAlgorithmParameterException("parameters must be " + DirectoryCertStoreParameters.class.getName());
    }
  }

  @Override
  public Collection<? extends Certificate> engineGetCertificates(CertSelector selector) throws CertStoreException {
    List<Certificate> certificates = new ArrayList<>();
    CertificateFactory factory;
    try {
      factory = CertificateFactory.getInstance("X.509");
    } catch (CertificateException e) {
      throw new CertStoreException("could not create X.509 factory", e);
    }
    try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(this.dirctory, "*.{pem,crt}}")) {
      for (Path certificateFile : directoryStream) {
        if (Files.isRegularFile(certificateFile)) {
          try (InputStream inputStream = Files.newInputStream(certificateFile)) { // TODO buffer?
            Certificate certificate;
            try {
              certificate = factory.generateCertificate(inputStream);
            } catch (CertificateException e) {
              throw new CertStoreException("could not create load certificate from file: " + certificateFile, e);
            }
            if ((selector == null) || selector.match(certificate)) {
              certificates.add(certificate);
            }
          }
        }
      }
    } catch (IOException e) {
      throw new CertStoreException("could not load certificates", e);
    }
    return certificates;
  }

  @Override
  public Collection<? extends CRL> engineGetCRLs(CRLSelector selector) throws CertStoreException {
    return Collections.emptySet();
  }

}
