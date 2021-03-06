package com.github.marschall.directorykeystore;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;

/**
 * Methods related to loading from and saving to pem files.
 */
final class PemIO {

  private PemIO() {
    throw new AssertionError("not instantaible");
  }

  static Collection<? extends Certificate> loadCertificates(CertificateFactory factory, Path certificateFile) throws IOException, CertificateException {
    try (InputStream inputStream = Files.newInputStream(certificateFile);
         Reader reader = new InputStreamReader(inputStream, StandardCharsets.US_ASCII);
         BufferedReader buffered = new BufferedReader(reader)) {

      Collection<Certificate> certificates = new ArrayList<>();
      StringBuilder base64Buffer = new StringBuilder();
      String line = buffered.readLine();
      while (line != null) {
        if (line.startsWith("-----BEGIN ")) {
          byte[] der = decodePart(buffered, base64Buffer);
          if (line.equals("-----BEGIN CERTIFICATE-----")) {
            certificates.add(factory.generateCertificate(new ByteArrayInputStream(der)));
          } else if (line.startsWith("-----BEGIN ") && line.endsWith(" KEY-----")) {
            Map<String, KeyFactory> keyFactories = null; // FIXME
            try {
              loadKey(keyFactories, line, der);
            } catch (InvalidKeySpecException e) {
              throw new CertificateException("could not load key from:" + certificateFile, e);
            }
          } else {
            throw new CertificateException("unexpected begin: '" + line + "'");
          }
        } else {
          // ignore anything outside of -----BEGIN -----END
        }
        line = buffered.readLine();
      }
      return certificates;
    }
  }

  private static byte[] decodePart(BufferedReader reader, StringBuilder buffer) throws IOException {
    buffer.setLength(0);
    String line = reader.readLine();
    while ((line != null) && !line.startsWith("-----END ")) {
      buffer.append(line);
      line = reader.readLine();
    }

    return Base64.getMimeDecoder().decode(buffer.toString());
  }

  private static Key loadKey(Map<String, KeyFactory> keyFactories, String begin, byte[] der) throws InvalidKeySpecException {
    EncodedKeyType keyType = determineKeyType(begin);
    KeySpec keySpec = keyType.getKeySpec(der);
    KeyFactory keyFactory = keyFactories.computeIfAbsent(keyType.getKeyAlgorithm(), PemIO::getKeyFactory);

    return keyType.getKeyLoader().loadKey(keyFactory, keySpec);
  }

  static Key loadKey(Map<String, KeyFactory> keyFactories, Path keyFile) throws IOException, InvalidKeySpecException {
    try (InputStream inputStream = Files.newInputStream(keyFile);
         Reader reader = new InputStreamReader(inputStream, StandardCharsets.US_ASCII);
         BufferedReader buffered = new BufferedReader(reader, 1024)) {

      String begin = buffered.readLine();
      EncodedKeyType keyType = determineKeyType(begin);

      String line = buffered.readLine();
      StringBuilder base64Buffer = new StringBuilder();
      while ((line != null) && !line.startsWith("-----END ")) {
        base64Buffer.append(line);
        line = buffered.readLine();
      }

      byte[] encodedKey = Base64.getMimeDecoder().decode(base64Buffer.toString());
      KeySpec keySpec = keyType.getKeySpec(encodedKey);
      KeyFactory keyFactory = keyFactories.computeIfAbsent(keyType.getKeyAlgorithm(), PemIO::getKeyFactory);

      return keyType.getKeyLoader().loadKey(keyFactory, keySpec);
    }
  }

  private static KeyFactory getKeyFactory(String algorithm) {
    try {
      return KeyFactory.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalArgumentException("unknown key algorithm: " + algorithm, e);
    }
  }

  private static EncodedKeyType determineKeyType(String line) throws InvalidKeySpecException {
    if (line.startsWith("-----BEGIN ")) {
      if (line.equals("-----BEGIN PRIVATE KEY-----")) {
        // TODO singleton
        return new PKCS8EncodedPrivateKey();
      } else if (line.equals("-----BEGIN PUBLIC KEY-----")) {
        // TODO singleton
        // return new PKCS8EncodedPublicKey();
        return new X509EncodedPublicKey("RSA");
      } else if (line.endsWith("PRIVATE KEY-----")) {
        String keyType = line.substring("-----BEGIN ".length(), line.length() - " PRIVATE KEY-----".length());
        // if (keyType.equals("EC")) {
        //   return new ECPrivateKey();
        // } else {
        return new X509EncodedPrivateKey(keyType);
        // }
      } else if (line.endsWith("PUBLIC KEY-----")) {
        String keyType = line.substring("-----BEGIN ".length(), line.length() - " PUBLIC KEY-----".length());
        return new X509EncodedPublicKey(keyType);
      }
      throw new InvalidKeySpecException("unknown key type:" + line);
    }
    throw new InvalidKeySpecException("unknown key type, expected -----BEGIN :" + line);
  }


  static abstract class EncodedKeyType {

    abstract String getKeyAlgorithm();

    abstract KeySpec getKeySpec(byte[] encoded);

    abstract KeyLoader getKeyLoader();

  }

  static abstract class PKCS8EncodedKey extends EncodedKeyType {

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

  static abstract class X509EncodedKey extends EncodedKeyType {

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

  static final class ECPrivateKey extends EncodedKeyType {

    @Override
    String getKeyAlgorithm() {
      return "EC";
    }

    @Override
    KeySpec getKeySpec(byte[] encoded) {
      return new PKCS8EncodedKeySpec(encoded);
    }

    @Override
    KeyLoader getKeyLoader() {
      return KeyLoader.PRIVATE_KEY;
    }

  }

  @FunctionalInterface
  interface KeyLoader {

    Key loadKey(KeyFactory keyFactory, KeySpec keySpec) throws InvalidKeySpecException;

    KeyLoader PUBLIC_KEY = (keyFactory, keySpec) -> keyFactory.generatePublic(keySpec);

    KeyLoader PRIVATE_KEY = (keyFactory, keySpec) -> keyFactory.generatePrivate(keySpec);

  }

}
