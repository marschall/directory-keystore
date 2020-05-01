package com.github.marschall.directorykeystore;

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
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class DirectoryCertStore extends CertStoreSpi {

  private Path dirctory;

  DirectoryCertStore(CertStoreParameters parameters) throws InvalidAlgorithmParameterException {
    super(parameters);
    // TODO Auto-generated constructor stub
  }

  @Override
  public Collection<? extends Certificate> engineGetCertificates(
          CertSelector selector) throws CertStoreException {
    List<Certificate> certificates = new ArrayList<>();
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(this.dirctory, "*.{pem,crt}}")) {
      for (Path path : directoryStream) {
        if (Files.isRegularFile(path)) {
          try (InputStream inputStream = Files.newInputStream(path)) {
            Certificate certificate = factory.generateCertificate(inputStream);
            if ((selector == null) || selector.match(certificate)) {
              certificates.add(certificate);
            }
          }
        }
      }
    }
    // TODO Auto-generated method stub
    return certificates;
  }

  private static boolean isCertificateFile(Path file) {
    if (!Files.isReadable(file)) {
      return false;
    }
  }

  @Override
  public Collection<? extends CRL> engineGetCRLs(CRLSelector selector)
          throws CertStoreException {
    // TODO Auto-generated method stub
    return null;
  }

}
