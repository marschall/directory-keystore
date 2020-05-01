package com.github.marschall.directorykeystore;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.Key;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;
import java.util.Objects;

public class DirectoryKeystore extends KeyStoreSpi {

  private volatile Path directory;

  @Override
  public Key engineGetKey(String alias, char[] password)
          throws NoSuchAlgorithmException, UnrecoverableKeyException {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Certificate[] engineGetCertificateChain(String alias) {
    return null;
  }

  @Override
  public Certificate engineGetCertificate(String alias) {
    Path certificatePath = this.getCertificatePath(alias);
    if (!Files.exists(certificatePath)) {
      return null;
    }
    CertificateFactory certificateFactory = this.getX509CertificateFactory();
    return this.loadCertificate(certificateFactory, certificatePath);
  }

  @Override
  public Date engineGetCreationDate(String alias) {
    Path certificatePath = this.getCertificatePath(alias);
    Map<String, Object> attributes;
    try {
      attributes = Files.readAttributes(certificatePath, "creationTime");
    } catch (IOException e) {
      // per contract
      return null;
    }
    FileTime creationTime = (FileTime) attributes.get("creationTime");
    return new Date(creationTime.toMillis());
  }

  @Override
  public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
    // TODO Auto-generated method stub

  }

  @Override
  public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
          throws KeyStoreException {
    // TODO Auto-generated method stub

  }

  @Override
  public void engineSetCertificateEntry(String alias, Certificate cert)
          throws KeyStoreException {
    // TODO Auto-generated method stub

  }

  @Override
  public void engineDeleteEntry(String alias) throws KeyStoreException {
    // TODO Auto-generated method stub

  }

  @Override
  public Enumeration<String> engineAliases() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public boolean engineContainsAlias(String alias) {
    // TODO Auto-generated method stub
    return false;
  }

  @Override
  public int engineSize() {
    // TODO Auto-generated method stub
    return 0;
  }

  @Override
  public boolean engineIsKeyEntry(String alias) {
    // TODO Auto-generated method stub
    return false;
  }

  @Override
  public boolean engineIsCertificateEntry(String alias) {
    // TODO Auto-generated method stub
    return false;
  }

  @Override
  public String engineGetCertificateAlias(Certificate cert) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public void engineStore(OutputStream stream, char[] password)
          throws IOException, NoSuchAlgorithmException, CertificateException {
    // TODO Auto-generated method stub

  }

  private Path getCertificatePath(String alias) {
    // TODO Auto-generated method stub
    return null;
  }

  private Certificate loadCertificate(CertificateFactory factory, Path certificateFile) {
    try (InputStream inputStream = Files.newInputStream(certificateFile)) { // TODO buffer?
      try {
        return factory.generateCertificate(inputStream);
      } catch (CertificateException e) {
        throw new IllegalStateException("could not create load certificate from file: " + certificateFile, e);
      }
    } catch (IOException e) {
      throw new IllegalStateException("could not create load certificate from file: " + certificateFile, e);
    }
  }

  private CertificateFactory getX509CertificateFactory() {
    CertificateFactory factory;
    try {
      factory = CertificateFactory.getInstance("X.509");
    } catch (CertificateException e) {
      throw new IllegalStateException("could not create X.509 factory", e);
    }
    return factory;
  }

  @Override
  public void engineLoad(InputStream stream, char[] password) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void engineLoad(LoadStoreParameter param)
          throws IOException, NoSuchAlgorithmException, CertificateException {
    Objects.requireNonNull(param, "param");
    if (!(param instanceof DirectorLoadStoreParameter)) {
      throw new IllegalArgumentException("parameter must be a " + DirectorLoadStoreParameter.class);
    }
    this.directory = ((DirectorLoadStoreParameter) param).getDirectory();
  }

}
