package com.github.marschall.directorykeystore;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.reflect.Constructor;
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
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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

  private final static byte[] LINE_SEPARATOR = "\r\n".getBytes(StandardCharsets.US_ASCII);

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
  public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
    // TODO Auto-generated method stub

  }

  @Override
  public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
    Lock writeLock = this.entriesLock.writeLock();
    writeLock.lock();
    try {
      KeystoreEntry entry = this.entries.get(alias);
      if ((entry != null) && (entry instanceof KeyEntry)) {
        throw new KeyStoreException("Cannot overwrite existing key");
      }
      this.entries.put(alias, new SingleCertificateEntry(new Date(), cert));
    } finally {
      writeLock.unlock();
    }
  }

  @Override
  public void engineDeleteEntry(String alias) throws KeyStoreException {
    Lock writeLock = this.entriesLock.writeLock();
    writeLock.lock();
    try {
      this.entries.remove(alias);
    } finally {
      writeLock.unlock();
    }
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
      // intentionally don't close as caller has to close
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

    CertificateFactory certificateFactory = getX509CertificateFactory();
    Map<String, KeyFactory> keyFactories = new HashMap<>(4);
    try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(directory, EXTENSIONS_GLOB)) {
      for (Path entryFile : directoryStream) {
        if (Files.isRegularFile(entryFile)) {
          String fileName = entryFile.getFileName().toString();
          if (fileName.length() > 4) { // skip ".key" ".pem" and ".crt"
            Date creationDate = getCreationDate(entryFile);
            KeystoreEntry entry;
            if (fileName.endsWith(".key")) {
              entry = this.loadKeyEntry(entryFile, creationDate, keyFactories);
            } else if (fileName.endsWith(".pem") || fileName.endsWith(".crt")) {
              CertificateEntry certificateEntry = this.loadCertificateEntry(entryFile, creationDate, certificateFactory);
              if (certificateEntry.isEmpty()) {
                // don't add empty certificate chains
                entry = null;
              } else {
                entry = certificateEntry;
              }
            } else {
              throw new IllegalStateException("unknown file extension: " + entryFile);
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

  private KeystoreEntry loadKeyEntry(Path keyFile, Date creationDate, Map<String, KeyFactory> keyFactories)
          throws IOException, CertificateException {

    // https://stackoverflow.com/questions/20065304/differences-between-begin-rsa-private-key-and-begin-private-key
    // https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#keyfactory-algorithms
    // https://crypto.stackexchange.com/questions/46893/is-there-a-specification-for-the-begin-rsa-private-key-format
    // https://gist.github.com/destan/b708d11bd4f403506d6d5bb5fe6a82c5

    Key key;
    try {
      key = loadKey(keyFactories, keyFile);
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

    Lock readLock = this.entriesLock.readLock();
    readLock.lock();
    try {
      for (Entry<String, KeystoreEntry> entry : this.entries.entrySet()) {
        String alias = entry.getKey();
        KeystoreEntry keystoreEntry = entry.getValue();
        if (keystoreEntry instanceof SingleCertificateEntry) {
          Path certificateFile = directory.resolve(alias + ".pem");
          saveCertificateAsPem(((SingleCertificateEntry) keystoreEntry).getCertificate(), certificateFile, keystoreEntry.getCreationDate());
        } else if (keystoreEntry instanceof CertificateChainEntry) {

        }
      }
    } finally {
      readLock.unlock();
    }
  }

  static Collection<? extends Certificate> loadCertificates(CertificateFactory factory, Path certificateFile) throws IOException, CertificateException {
    try (InputStream inputStream = Files.newInputStream(certificateFile);
         BufferedInputStream buffered = new BufferedInputStream(inputStream)) {
      return factory.generateCertificates(buffered);
    }
  }

  private static Key loadKey(Map<String, KeyFactory> keyFactories, Path keyFile) throws IOException, InvalidKeySpecException {
    try (InputStream inputStream = Files.newInputStream(keyFile);
         Reader reader = new InputStreamReader(inputStream, StandardCharsets.US_ASCII);
         BufferedReader buffered = new BufferedReader(reader, 1024)) {

      String begin = buffered.readLine();
      EncodedKeyKeyType keyType = determineKeyType(begin);


      String line = buffered.readLine();
      StringBuilder base64Buffer = new StringBuilder();
      while ((line != null) && !line.startsWith("-----END ")) {
        base64Buffer.append(line);
        line = buffered.readLine();
      }

      byte[] encodedKey = Base64.getMimeDecoder().decode(base64Buffer.toString());
      KeySpec keySpec = keyType.getKeySpec(encodedKey);
      KeyFactory keyFactory = keyFactories.computeIfAbsent(keyType.getKeyAlgorithm(), DirectoryKeystore::getKeyFactory);

      return keyType.getKeyLoader().loadKey(keyFactory, keySpec);
    }
  }

  private static void saveCertificateAsPem(Certificate certificate, Path certificateFile, Date creationDate) throws IOException, CertificateEncodingException {
    try (OutputStream outputStream = Files.newOutputStream(certificateFile);
         BufferedOutputStream buffered = new BufferedOutputStream(outputStream, 2048)) { // 2048 should be enough for most certificates
      buffered.write(BEGIN_CERTIFICATE);
      buffered.write(LINE_SEPARATOR);
      byte[] encoded = Base64.getMimeEncoder(PEM_LINE_ENGTH, LINE_SEPARATOR).encode(certificate.getEncoded());
      buffered.write(encoded);
      buffered.write(LINE_SEPARATOR);
      buffered.write(END_CERTIFICATE);
      buffered.write(LINE_SEPARATOR);
    }
    Files.setAttribute(certificateFile, "creationTime", FileTime.from(creationDate.toInstant()));
  }

  private static void saveCertificateAsDer(Certificate certificate, Path certificateFile, Date creationDate) throws IOException, CertificateEncodingException {
    try (OutputStream outputStream = Files.newOutputStream(certificateFile)) {
      outputStream.write(certificate.getEncoded());
    }
    Files.setAttribute(certificateFile, "creationTime", FileTime.from(creationDate.toInstant()));
  }

  static CertificateFactory getX509CertificateFactory() throws CertificateException {
    return CertificateFactory.getInstance("X.509");
  }

  private static KeyFactory getKeyFactory(String algorithm) {
    try {
      return KeyFactory.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalArgumentException("unknown key algorithm: " + algorithm, e);
    }
  }

  private static EncodedKeyKeyType determineKeyType(String line) throws InvalidKeySpecException {
    if (line.startsWith("-----BEGIN ")) {
      if (line.equals("-----BEGIN PRIVATE KEY-----")) {
        // TODO singleton
        return new PKCS8EncodedPrivateKey();
      } else if (line.equals("-----BEGIN PUBLIC KEY-----")) {
        // TODO singleton
//        return new PKCS8EncodedPublicKey();
        return new X509EncodedPublicKey("RSA");
      } else if (line.endsWith("PRIVATE KEY-----")) {
        String keyType = line.substring("-----BEGIN ".length(), line.length() - " PRIVATE KEY-----".length());
        return new X509EncodedPrivateKey(keyType);
      } else if (line.endsWith("PUBLIC KEY-----")) {
        String keyType = line.substring("-----BEGIN ".length(), line.length() - " PUBLIC KEY-----".length());
        return new X509EncodedPublicKey(keyType);
      }
      throw new InvalidKeySpecException("unknown key type:" + line);
    }
    throw new InvalidKeySpecException("unknown key type, expected -----BEGIN :" + line);
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
    return Date.from(creationTime.toInstant());
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

    // TODO
    // private final Certificate[] certificates;

    KeyEntry(Date creationDate, Key key) {
      super(creationDate);
      this.key = key;
    }

    Key getKey() {
      return this.key;
    }

  }

  static abstract class EncodedKeyKeyType {

    abstract String getKeyAlgorithm();

    abstract KeySpec getKeySpec(byte[] encoded);

    abstract KeyLoader getKeyLoader();

  }

  static abstract class PKCS8EncodedKey extends EncodedKeyKeyType {

    @Override
    String getKeyAlgorithm() {
      // TODO
      return "RSA";
    }

    @Override
    KeySpec getKeySpec(byte[] encoded) {
      return new PKCS8EncodedKeySpec(encoded);
    }

  }

  static final class PKCS8EncodedPrivateKey extends PKCS8EncodedKey {

    @Override
    KeyLoader getKeyLoader() {
      return KeyLoader.PRIVATE_KEY;
    }

  }

  static final class PKCS8EncodedPublicKey extends PKCS8EncodedKey {

    @Override
    KeyLoader getKeyLoader() {
      return KeyLoader.PUBLIC_KEY;
    }

  }

  static abstract class X509EncodedKey extends EncodedKeyKeyType {

    private final String keyAlgorithm;
    private static final MethodHandle NEW_X509_ENCODED_KEY_SPEC;

    static {
      Lookup lookup = MethodHandles.publicLookup();
      MethodHandle constructorHandle;
      try {
        try {
          Constructor<X509EncodedKeySpec> java9Constructor = X509EncodedKeySpec.class.getConstructor(byte[].class, String.class);
          constructorHandle = lookup.unreflectConstructor(java9Constructor);
        } catch (NoSuchMethodException e) {
          Constructor<X509EncodedKeySpec> java8Constructor = X509EncodedKeySpec.class.getConstructor(byte[].class);
          MethodHandle java8ConstructorHandle = lookup.unreflectConstructor(java8Constructor);
          constructorHandle = MethodHandles.dropArguments(java8ConstructorHandle, 1, String.class);
        }
      } catch (IllegalAccessException | NoSuchMethodException e) {
        throw new RuntimeException("could not find matching X509EncodedKeySpec constructor", e);
      }
      NEW_X509_ENCODED_KEY_SPEC = constructorHandle;
    }

    X509EncodedKey(String keyAlgorithm) {
      this.keyAlgorithm = keyAlgorithm;
    }

    @Override
    String getKeyAlgorithm() {
      return this.keyAlgorithm;
    }

    @Override
    KeySpec getKeySpec(byte[] encoded) {
      try {
        return (X509EncodedKeySpec) NEW_X509_ENCODED_KEY_SPEC.invokeExact(encoded, this.keyAlgorithm);
      } catch (Error | RuntimeException e) {
        throw e;
      } catch (Throwable e) {
        throw new IllegalStateException("could not call X509EncodedKeySpec constructor", e);
      }
    }

  }

  static final class X509EncodedPrivateKey extends X509EncodedKey {

    X509EncodedPrivateKey(String keyAlgorithm) {
      super(keyAlgorithm);
    }

    @Override
    KeyLoader getKeyLoader() {
      return KeyLoader.PRIVATE_KEY;
    }

  }

  static final class X509EncodedPublicKey extends X509EncodedKey {

    X509EncodedPublicKey(String keyAlgorithm) {
      super(keyAlgorithm);
    }

    @Override
    KeyLoader getKeyLoader() {
      return KeyLoader.PUBLIC_KEY;
    }

  }

  @FunctionalInterface
  interface KeyLoader {

    Key loadKey(KeyFactory keyFactory, KeySpec keySpec) throws InvalidKeySpecException;

    KeyLoader PUBLIC_KEY = (keyFactory, keySpec) -> keyFactory.generatePublic(keySpec);

    KeyLoader PRIVATE_KEY = (keyFactory, keySpec) -> keyFactory.generatePrivate(keySpec);

  }

}
