package com.github.marschall.directorykeystore;

import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.CertStore;

/**
 * A security provider that a registers directory based {@link KeyStore}
 * and {@link CertStore} implementations.
 */
public final class DirectoryKeystoreProvider extends Provider {

  /**
   * The name of this security provider.
   */
  public static final String NAME = "directory";

  /**
   * The type of keystore that uses directories to store certificates.
   */
  public static final String TYPE = "directory";

  /**
   * Default constructor, either called directly by programmatic registration or
   * by JCA.
   */
  public DirectoryKeystoreProvider() {
    super(NAME, 0.1d, "directory (KeyStore)");
    this.put("KeyStore." + TYPE, DirectoryKeystore.class.getName());
    this.put("CertStore." + TYPE, DirectoryCertStore.class.getName());
  }

}
