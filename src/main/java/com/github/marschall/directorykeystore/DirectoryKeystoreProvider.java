package com.github.marschall.directorykeystore;

import java.security.Provider;

public final class DirectoryKeystoreProvider extends Provider {

  /**
   * The name of this security provider.
   */
  public static final String NAME = "directory";

  /**
   * The type of this keystore provider that uses directories to store certificates.
   */
  public static final String TYPE = "directory";

  public DirectoryKeystoreProvider() {
    super(NAME, 0.1d, "directory");
    this.put("KeyStore." + TYPE, DirectoryKeystore.class.getName());
    this.put("CertStore." + TYPE, DirectoryCertStore.class.getName());
  }

}
