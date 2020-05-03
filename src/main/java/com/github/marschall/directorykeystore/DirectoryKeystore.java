package com.github.marschall.directorykeystore;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public final class DirectoryKeystore extends KeyStoreSpi {

  // https://tools.ietf.org/html/rfc1421
  // with each line except the last containing exactly 64
  // printable characters and the final line containing 64 or fewer
  // printable characters
  private static final int PEM_LINE_ENGTH = 64;

  private static final byte[] BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----".getBytes(StandardCharsets.US_ASCII);

  private static final byte[] END_CERTIFICATE = "-----END CERTIFICATE-----".getBytes(StandardCharsets.US_ASCII);

  private final static byte[] LINE_SEPARATOR = System.getProperty("line.separator").getBytes(StandardCharsets.US_ASCII);

  private final Map<String, KeystoreEntry> entries;

  private final ReadWriteLock entriesLock;

  public DirectoryKeystore() {
    this.entries = new HashMap<>();
    this.entriesLock = new ReentrantReadWriteLock();
  }

  @Override
  public Key engineGetKey(String alias, char[] password) {
    KeystoreEntry entry = this.getEntry(alias);
    if (entry instanceof KeyEntry) {
      return ((KeyEntry) entry).getKey();
    } else {
      return null;
    }
  }

  @Override
  public Certificate[] engineGetCertificateChain(String alias) {
    return null;
  }

  private KeystoreEntry getEntry(String alias) {
    Lock readLock = this.entriesLock.readLock();
    readLock.lock();
    try {
      return this.entries.get(alias);
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public Certificate engineGetCertificate(String alias) {
    KeystoreEntry entry = this.getEntry(alias);
    if (entry instanceof CertificateEntry) {
      return ((CertificateEntry) entry).getCertificate();
    } else {
      return null;
    }
  }

  @Override
  public Date engineGetCreationDate(String alias) {
    KeystoreEntry entry = this.getEntry(alias);
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
    Lock readLock = this.entriesLock.readLock();
    readLock.lock();
    try {
      // copy to return a snapshot in time
      return Collections.enumeration(new ArrayList<>(this.entries.keySet()));
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public boolean engineContainsAlias(String alias) {
    Lock readLock = this.entriesLock.readLock();
    readLock.lock();
    try {
      return this.entries.containsKey(alias);
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public int engineSize() {
    Lock readLock = this.entriesLock.readLock();
    readLock.lock();
    try {
      return this.entries.size();
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public boolean engineIsKeyEntry(String alias) {
    return false;
  }

  @Override
  public boolean engineIsCertificateEntry(String alias) {
    KeystoreEntry entry = this.getEntry(alias);
    return entry instanceof CertificateEntry;
  }

  @Override
  public String engineGetCertificateAlias(Certificate cert) {
    Lock readLock = this.entriesLock.readLock();
    readLock.lock();
    try {
      for (Entry<String, KeystoreEntry> entry : this.entries.entrySet()) {
        KeystoreEntry keystoreEntry = entry.getValue();
        if (keystoreEntry instanceof CertificateEntry) {
          CertificateEntry certificateEntry = (CertificateEntry) keystoreEntry;
          if (certificateEntry.getCertificate().equals(cert)) {
            return entry.getKey();
          }
        }
      }
    } finally {
      readLock.unlock();
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

    Map<String, KeystoreEntry> certificates = new HashMap<>();

    // load certificates
    CertificateFactory certificateFactory = this.getX509CertificateFactory();
    try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(directory, "*.{pem,crt}")) {
      for (Path certificateFile : directoryStream) {
        if (Files.isRegularFile(certificateFile)) {
          String fileName = certificateFile.getFileName().toString();
          if (fileName.length() > 4) { // skip ".pem" and ".crt"
            Certificate certificate = loadCertificate(certificateFactory, certificateFile);
            Date creationDate = getCreationDate(certificateFile);
            String alias = getAlias(fileName);
            // TODO check pem replaces crt with same name
            certificates.put(alias, new CertificateEntry(creationDate, certificate));
          }
        }
      }
    }

    // load keys
    KeyFactory keyFactory = this.getKeyFactory();
    try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(directory, "*.key")) {
      for (Path keyFile : directoryStream) {
        if (Files.isRegularFile(keyFile)) {
          String fileName = keyFile.getFileName().toString();
          if (fileName.length() > 4) { // skip ".key"
            Key key;
            try {
              key = loadKey(keyFactory, keyFile);
            } catch (InvalidKeySpecException e) {
              throw new CertificateException("could not load key from:" + keyFile, e);
            }
            Date creationDate = getCreationDate(keyFile);
            String alias = getAlias(fileName);
            certificates.put(alias, new KeyEntry(creationDate, key));
          }
        }
      }
    }

    Lock writeLock = this.entriesLock.writeLock();
    writeLock.lock();
    try {
      this.entries.clear();
      this.entries.putAll(certificates);
    } finally {
      writeLock.unlock();
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

  private static Key loadKey(KeyFactory factory, Path keyFile) throws IOException, InvalidKeySpecException {
    try (InputStream inputStream = Files.newInputStream(keyFile);
         BufferedInputStream buffered = new BufferedInputStream(inputStream)) {
      byte[] allBytes = Files.readAllBytes(keyFile);
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(allBytes));
      return factory.generatePrivate(keySpec);
    }
  }

  private static void saveCertificateAsPem(Certificate certificate, Path certificateFile) throws IOException, CertificateEncodingException {
    try (OutputStream outputStream = Files.newOutputStream(certificateFile);
         BufferedOutputStream buffered = new BufferedOutputStream(outputStream, 2048)) { // 2048 should be enough for most certificates
      buffered.write(BEGIN_CERTIFICATE);
      buffered.write(LINE_SEPARATOR);
      byte[] encoded = Base64.getMimeEncoder(PEM_LINE_ENGTH, LINE_SEPARATOR).encode(certificate.getEncoded());
      buffered.write(encoded);
      buffered.write(END_CERTIFICATE);
      buffered.write(LINE_SEPARATOR);
    }
  }

  private static void saveCertificateAsDer(Certificate certificate, Path certificateFile) throws IOException, CertificateEncodingException {
    try (OutputStream outputStream = Files.newOutputStream(certificateFile)) {
      outputStream.write(certificate.getEncoded());
    }
  }

  private CertificateFactory getX509CertificateFactory() throws CertificateException {
    return CertificateFactory.getInstance("X.509");
  }

  private KeyFactory getKeyFactory() throws NoSuchAlgorithmException {
    // https://gist.github.com/destan/b708d11bd4f403506d6d5bb5fe6a82c5
    return KeyFactory.getInstance("RSA");
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

  static class KeystoreEntry {

    private final Date creationDate;

    KeystoreEntry(Date creationDate) {
      this.creationDate = creationDate;
    }

    Date getCreationDate() {
      return this.creationDate;
    }

  }

  static final class CertificateEntry extends KeystoreEntry {

    private final Certificate certificate;

    CertificateEntry(Date creationDate, Certificate certificate) {
      super(creationDate);
      this.certificate = certificate;
    }

    Certificate getCertificate() {
      return this.certificate;
    }

  }

  static final class KeyEntry extends KeystoreEntry {

    private final Key key;

    KeyEntry(Date creationDate, Key key) {
      super(creationDate);
      this.key = key;
    }

    Key getKey() {
      return this.key;
    }

  }

}
