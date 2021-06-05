module com.github.marschall.directorykeystore {

  exports com.github.marschall.directorykeystore;

  provides java.security.Provider
      with com.github.marschall.directorykeystore.DirectoryKeystoreProvider;

}