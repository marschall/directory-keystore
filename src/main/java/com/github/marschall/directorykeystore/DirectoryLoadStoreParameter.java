package com.github.marschall.directorykeystore;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.ProtectionParameter;
import java.util.Objects;

/**
 * Specifies how to load and safe a keystore.
 * 
 * @see java.security.KeyStore#load(LoadStoreParameter)
 * @see java.security.KeyStore#store(LoadStoreParameter)
 */
public final class DirectoryLoadStoreParameter implements LoadStoreParameter {

  private final Path directory;

  /**
   * Constructs a new {@link DirectoryLoadStoreParameter}
   * 
   * @param certificateDirectory the directory from which to load and store
   *                             certificates and keys,
   *                             must exist, must be a directory, must not be null,
   *                             can be on any file system
   * @throws NullPointerException if {@code certificateDirectory} is {@code null}
   * @throws IllegalArgumentException if {@code certificateDirectory} is {@code null}
   */
  public DirectoryLoadStoreParameter(Path certificateDirectory) {
    Objects.requireNonNull(certificateDirectory, "certificateDirectory");
    if (!Files.isDirectory(certificateDirectory)) {
      throw new IllegalArgumentException("certificateDirectory must be a directory");
    }
    this.directory = certificateDirectory;
  }

  @Override
  public ProtectionParameter getProtectionParameter() {
    return null;
  }

  Path getDirectory() {
    return this.directory;
  }

}
