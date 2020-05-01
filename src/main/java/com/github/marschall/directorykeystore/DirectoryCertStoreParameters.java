package com.github.marschall.directorykeystore;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertStoreParameters;
import java.util.Objects;

public final class DirectoryCertStoreParameters implements CertStoreParameters {

  private final Path directory;

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
