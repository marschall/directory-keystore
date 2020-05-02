package com.github.marschall.directorykeystore;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.Key;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;

public final class DirectoryKeystore extends KeyStoreSpi {

  private final Map<String, CertificateEntry> certificates;

  public DirectoryKeystore() {
    this.certificates = Collections.synchronizedMap(new HashMap<>());
  }

  @Override
  public Key engineGetKey(String alias, char[] password) {
    return null;
  }

  @Override
  public Certificate[] engineGetCertificateChain(String alias) {
    return null;
  }

  @Override
  public Certificate engineGetCertificate(String alias) {
    CertificateEntry entry = this.certificates.get(alias);
    if (entry != null) {
      return entry.getCertificate();
    } else {
      return null;
    }
  }

  @Override
  public Date engineGetCreationDate(String alias) {
    CertificateEntry entry = this.certificates.get(alias);
    if (entry != null) {
      return entry.getCreationDate();
    } else {
      return null;
    }
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
    return Collections.enumeration(this.certificates.keySet());
  }

  @Override
  public boolean engineContainsAlias(String alias) {
    return this.certificates.containsKey(alias);
  }

  @Override
  public int engineSize() {
    return this.certificates.size();
  }

  @Override
  public boolean engineIsKeyEntry(String alias) {
    return false;
  }

  @Override
  public boolean engineIsCertificateEntry(String alias) {
    return this.certificates.containsKey(alias);
  }

  @Override
  public String engineGetCertificateAlias(Certificate cert) {
    synchronized (this.certificates) {
      for (Entry<String, CertificateEntry> entry : this.certificates.entrySet()) {
        if (entry.getValue().getCertificate().equals(cert)) {
          return entry.getKey();
        }
      }
    }
    return null;
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
    Path directory = ((DirectorLoadStoreParameter) param).getDirectory();

    Map<String, CertificateEntry> certificates = new HashMap<>();
    CertificateFactory factory = this.getX509CertificateFactory();
    try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(directory, "*.{pem,crt}")) {
      for (Path certificateFile : directoryStream) {
        if (Files.isRegularFile(certificateFile)) {
          String fileName = certificateFile.getFileName().toString();
          if (fileName.length() > 4) { // skip ".pem" and ".crt"
            Certificate certificate = loadCertificate(factory, certificateFile);
            Date creationDate = getCreationDate(certificateFile);
            String alias = getAlias(fileName);
            // TODO check pem replaces crt with same name
            certificates.put(alias, new CertificateEntry(creationDate, certificate));
          }
        }
      }
    }
    synchronized (this.certificates) {
      this.certificates.clear();
      this.certificates.putAll(certificates);
    }
  }


  static String getAlias(String fileName) {
    return fileName.substring(0, fileName.lastIndexOf('.'));
  }

  @Override
  public void engineStore(OutputStream stream, char[] password) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void engineStore(LoadStoreParameter param)
          throws IOException, NoSuchAlgorithmException, CertificateException {
    Objects.requireNonNull(param, "param");
    if (!(param instanceof DirectorLoadStoreParameter)) {
      throw new IllegalArgumentException("parameter must be a " + DirectorLoadStoreParameter.class);
    }
    Path directory = ((DirectorLoadStoreParameter) param).getDirectory();
  }



  private static Certificate loadCertificate(CertificateFactory factory, Path certificateFile) throws IOException, CertificateException {
    try (InputStream inputStream = Files.newInputStream(certificateFile);
         BufferedInputStream buffered = new BufferedInputStream(inputStream)) {
      return factory.generateCertificate(buffered);
    }
  }


  private CertificateFactory getX509CertificateFactory() throws CertificateException {
    return CertificateFactory.getInstance("X.509");
  }

  private static Date getCreationDate(Path path) {
    Map<String, Object> attributes;
    try {
      attributes = Files.readAttributes(path, "creationTime");
    } catch (IOException e) {
      // per contract
      return null;
    }
    FileTime creationTime = (FileTime) attributes.get("creationTime");
    return new Date(creationTime.toMillis());
  }

  static final class CertificateEntry {

    private final Date creationDate;

    private final Certificate certificate;

    CertificateEntry(Date creationDate, Certificate certificate) {
      this.creationDate = creationDate;
      this.certificate = certificate;
    }

    Date getCreationDate() {
      return this.creationDate;
    }

    Certificate getCertificate() {
      return this.certificate;
    }

  }

}
