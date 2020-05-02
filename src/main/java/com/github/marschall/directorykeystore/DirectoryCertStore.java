package com.github.marschall.directorykeystore;

import java.io.BufferedInputStream;
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

public final class DirectoryCertStore extends CertStoreSpi {

  private final Path directory;

  public DirectoryCertStore(CertStoreParameters parameters) throws InvalidAlgorithmParameterException {
    super(parameters);
    if (!(parameters instanceof DirectoryCertStoreParameters)) {
      throw new InvalidAlgorithmParameterException("parameters must be " + DirectoryCertStoreParameters.class.getName());
    }
    this.directory = ((DirectoryCertStoreParameters) parameters).getDirectory();
  }

  @Override
  public Collection<? extends Certificate> engineGetCertificates(CertSelector selector) throws CertStoreException {
    List<Certificate> certificates = new ArrayList<>();
    CertificateFactory factory = this.getX509CertificateFactory();
    try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(this.directory, "*.{pem,crt}")) {
      for (Path certificateFile : directoryStream) {
        if (Files.isRegularFile(certificateFile)) {
          Certificate certificate = this.loadCertificate(factory, certificateFile);
          if ((selector == null) || selector.match(certificate)) {
            certificates.add(certificate);
          }
        }
      }
    } catch (IOException e) {
      throw new CertStoreException("could not load certificates from: " + this.directory, e);
    }
    return certificates;
  }

  private CertificateFactory getX509CertificateFactory() throws CertStoreException {
    CertificateFactory factory;
    try {
      factory = CertificateFactory.getInstance("X.509");
    } catch (CertificateException e) {
      throw new CertStoreException("could not create X.509 factory", e);
    }
    return factory;
  }

  private Certificate loadCertificate(CertificateFactory factory, Path certificateFile) throws CertStoreException {
    try (InputStream inputStream = Files.newInputStream(certificateFile);
         BufferedInputStream buffered = new BufferedInputStream(inputStream)) {
      try {
        return factory.generateCertificate(buffered);
      } catch (CertificateException e) {
        throw new CertStoreException("could not create load certificate from file: " + certificateFile, e);
      }
    } catch (IOException e) {
      throw new CertStoreException("could not create load certificate from file: " + certificateFile, e);
    }
  }

  @Override
  public Collection<? extends CRL> engineGetCRLs(CRLSelector selector) throws CertStoreException {
    return Collections.emptySet();
  }

}
