package com.github.marschall.directorykeystore;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
import java.util.Collection;
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

  // TODO watch service

  // file names
  // https://support.ssl.com/Knowledgebase/Article/View/19/0/der-vs-crt-vs-cer-vs-pem-certificates-and-how-to-convert-them
  private static final String EXTENSIONS_GLOB = "*.{pem,crt,key}";


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

  /**
   * Default constructor for JCA, should not be called directly.
   */
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
    KeystoreEntry entry = this.getEntry(alias);
    if (entry instanceof SingleCertificateEntry) {
      return new Certificate[] {((SingleCertificateEntry) entry).getCertificate()};
    } else if (entry instanceof CertificateChainEntry) {
      // TODO copy?
      return ((CertificateChainEntry) entry).getCertificates();
    } else {
      return null;
    }
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
    if (entry instanceof SingleCertificateEntry) {
      return ((SingleCertificateEntry) entry).getCertificate();
    } else if (entry instanceof CertificateChainEntry) {
      return ((CertificateChainEntry) entry).getCertificates()[0];
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
    KeystoreEntry entry = this.getEntry(alias);
    return entry instanceof KeyEntry;
  }

  @Override
  public boolean engineIsCertificateEntry(String alias) {
    KeystoreEntry entry = this.getEntry(alias);
    return (entry instanceof SingleCertificateEntry) || (entry instanceof CertificateChainEntry);
  }

  @Override
  public String engineGetCertificateAlias(Certificate cert) {
    Lock readLock = this.entriesLock.readLock();
    readLock.lock();
    try {
      for (Entry<String, KeystoreEntry> entry : this.entries.entrySet()) {
        KeystoreEntry keystoreEntry = entry.getValue();
        if (keystoreEntry instanceof SingleCertificateEntry) {
          SingleCertificateEntry certificateEntry = (SingleCertificateEntry) keystoreEntry;
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
  public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
    if (stream == null) {
      this.initializeEmpty();
    } else {
      // intentionally don't close as call has to close
      BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(stream), 1024); // use default charset
      String location = bufferedReader.readLine();
      LoadStoreParameter loadStoreParameter = new DirectorLoadStoreParameter(Paths.get(location));
      this.engineLoad(loadStoreParameter);
    }
  }

  @Override
  public void engineLoad(LoadStoreParameter param) throws IOException, NoSuchAlgorithmException, CertificateException {
    if (param == null) {
      this.initializeEmpty();
      return;
    }
    Path directory = ((DirectorLoadStoreParameter) param).getDirectory();

    Map<String, KeystoreEntry> loadedEntries = new HashMap<>();

    CertificateFactory certificateFactory = this.getX509CertificateFactory();
    KeyFactory keyFactory = this.getKeyFactory();
    try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(directory, EXTENSIONS_GLOB)) {
      for (Path certificateFile : directoryStream) {
        if (Files.isRegularFile(certificateFile)) {
          String fileName = certificateFile.getFileName().toString();
          if (fileName.length() > 4) { // skip ".key" ".pem" and ".crt"
            Date creationDate = getCreationDate(certificateFile);
            KeystoreEntry entry;
            if (fileName.endsWith(".key")) {
              entry = this.loadKeyEntry(directory, creationDate, keyFactory);
            } else if (fileName.endsWith(".pem") || fileName.endsWith(".crt")) {
              CertificateEntry certificateEntry = this.loadCertificateEntry(certificateFile, creationDate, certificateFactory);
              if (certificateEntry.isEmpty()) {
                entry = null;
              } else {
                entry = certificateEntry;
              }
            } else {
              throw new IllegalStateException("unknown file extension: " + certificateFile);
            }

            if (entry != null) {
              String alias = getAlias(fileName);
              loadedEntries.put(alias, entry);
            }
          }
        }
      }
    }

    this.initializeFromMap(loadedEntries);
  }

  private CertificateEntry loadCertificateEntry(Path certificateFile, Date creationDate, CertificateFactory certificateFactory)
          throws IOException, CertificateException {

    Collection<? extends Certificate> certificates = loadCertificates(certificateFactory, certificateFile);
    switch (certificates.size()) {
      case 0:
        return new EmptyCertificateChainEntry(creationDate);
      case 1:
        return new SingleCertificateEntry(creationDate, certificates.iterator().next());
      default:
        return new CertificateChainEntry(creationDate, certificates.toArray(new Certificate[0]));
    }
  }

  private KeystoreEntry loadKeyEntry(Path keyFile, Date creationDate, KeyFactory keyFactory)
          throws IOException, CertificateException {

    // https://stackoverflow.com/questions/20065304/differences-between-begin-rsa-private-key-and-begin-private-key
    // https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#keyfactory-algorithms
    // https://crypto.stackexchange.com/questions/46893/is-there-a-specification-for-the-begin-rsa-private-key-format

    Key key;
    try {
      key = loadKey(keyFactory, keyFile);
    } catch (InvalidKeySpecException e) {
      throw new CertificateException("could not load key from:" + keyFile, e);
    }
    return new KeyEntry(creationDate, key);
  }

  private void initializeEmpty() {
    this.initializeFromMap(Collections.emptyMap());
  }

  private void initializeFromMap(Map<String, KeystoreEntry> newEntries) {
    Lock writeLock = this.entriesLock.writeLock();
    writeLock.lock();
    try {
      this.entries.clear();
      this.entries.putAll(newEntries);
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
    Files.createDirectories(directory);

    // delete current keystore entries
    try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(directory, EXTENSIONS_GLOB)) {
      for (Path keystoreFile : directoryStream) {
        if (!Files.isDirectory(keystoreFile)) {
          String fileName = keystoreFile.getFileName().toString();
          if (fileName.length() > 4) { // skip ".key" ".pem" and ".crt" because they also won't be loaded
            Files.delete(keystoreFile);
          }
        }
      }
    }
  }

  private static Collection<? extends Certificate> loadCertificates(CertificateFactory factory, Path certificateFile) throws IOException, CertificateException {
    try (InputStream inputStream = Files.newInputStream(certificateFile);
         BufferedInputStream buffered = new BufferedInputStream(inputStream)) {
      return factory.generateCertificates(buffered);
    }
  }

  private static Key loadKey(KeyFactory factory, Path keyFile) throws IOException, InvalidKeySpecException {
    try (InputStream inputStream = Files.newInputStream(keyFile);
         BufferedInputStream buffered = new BufferedInputStream(inputStream)) {
      byte[] allBytes = Files.readAllBytes(keyFile);
      // X509EncodedKeySpec for PKCS#1
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

  static abstract class KeystoreEntry {

    private final Date creationDate;

    KeystoreEntry(Date creationDate) {
      this.creationDate = creationDate;
    }

    Date getCreationDate() {
      return this.creationDate;
    }

  }

  static abstract class CertificateEntry extends KeystoreEntry {

    CertificateEntry(Date creationDate) {
      super(creationDate);
    }

    abstract boolean isEmpty();

  }

  static final class EmptyCertificateChainEntry extends CertificateEntry {

    EmptyCertificateChainEntry(Date creationDate) {
      super(creationDate);
    }

    @Override
    boolean isEmpty() {
      return true;
    }

  }

  static final class SingleCertificateEntry extends CertificateEntry {

    private final Certificate certificate;

    SingleCertificateEntry(Date creationDate, Certificate certificate) {
      super(creationDate);
      this.certificate = certificate;
    }

    Certificate getCertificate() {
      return this.certificate;
    }

    @Override
    boolean isEmpty() {
      return false;
    }

  }

  static final class CertificateChainEntry extends CertificateEntry {

    private final Certificate[] certificates;

    CertificateChainEntry(Date creationDate, Certificate[] certificates) {
      super(creationDate);
      this.certificates = certificates;
    }

    Certificate[] getCertificates() {
      return this.certificates;
    }

    @Override
    boolean isEmpty() {
      return false;
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
