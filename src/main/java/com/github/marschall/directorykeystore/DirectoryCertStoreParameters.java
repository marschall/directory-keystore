package com.github.marschall.directorykeystore;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore.LoadStoreParameter;
import java.security.cert.CertStoreParameters;
import java.util.Objects;

/**
 * Specifies how to load a cert store.
 * 
 * @see java.security.cert.CertStore#getInstance(String, CertStoreParameters)
 */
public final class DirectoryCertStoreParameters implements CertStoreParameters {

  private final Path directory;

  /**
   * Constructs a new {@link DirectoryCertStoreParameters}
   * 
   * @param certificateDirectory the directory from which to load certificates,
   *                             must exist, must be a directory, must not be null,
   *                             can be on any file system
   * @throws NullPointerException if {@code certificateDirectory} is {@code null}
   * @throws IllegalArgumentException if {@code certificateDirectory} is {@code null}
   */
  public DirectoryCertStoreParameters(Path certificateDirectory) {
    Objects.requireNonNull(certificateDirectory, "certificateDirectory");
    if (!Files.isDirectory(certificateDirectory)) {
      throw new IllegalArgumentException("certificateDirectory must be a directory");
    }
    this.directory = certificateDirectory;
  }

  Path getDirectory() {
    return this.directory;
  }

  @Override
  public Object clone() {
    try {
      return super.clone();
    } catch (CloneNotSupportedException e) {
      // Cannot happen
      throw new InternalError("clone not supported", e);
    }
  }

}
