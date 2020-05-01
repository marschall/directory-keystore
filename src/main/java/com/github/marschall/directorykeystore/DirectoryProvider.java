package com.github.marschall.directorykeystore;

import java.security.Provider;

public final class DirectoryProvider extends Provider {

  /**
   * The name of this security provider.
   */
  public static final String NAME = "directory";

  /**
   * The name algorithm that uses getrandom() with a blocking device (/dev/random).
   */
  public static final String DIRECTORY = "directory";

  public DirectoryProvider() {
    super(NAME, 0.1d, "getrandom (SecureRandom)");
    this.put("KeyStore." + DIRECTORY, DirectoryKeystore.class.getName());
    this.put("SecureRandom." + DIRECTORY + " ThreadSafe", "true");
  }

}
