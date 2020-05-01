package com.github.marschall.directorykeystore;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.ProtectionParameter;
import java.util.Objects;

public final class DirectorLoadStoreParameter implements LoadStoreParameter {

  private final Path directory;

  public DirectorLoadStoreParameter(Path certificateDirectory) {
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
