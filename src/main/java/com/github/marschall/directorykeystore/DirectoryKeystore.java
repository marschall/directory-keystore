package com.github.marschall.directorykeystore;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;

public class DirectoryKeystore extends KeyStoreSpi {

  @Override
  public Key engineGetKey(String alias, char[] password)
          throws NoSuchAlgorithmException, UnrecoverableKeyException {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Certificate[] engineGetCertificateChain(String alias) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Certificate engineGetCertificate(String alias) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Date engineGetCreationDate(String alias) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public void engineSetKeyEntry(String alias, Key key, char[] password,
          Certificate[] chain) throws KeyStoreException {
    // TODO Auto-generated method stub

  }

  @Override
  public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
          throws KeyStoreException {
    // TODO Auto-generated method stub

  }

  @Override
  public void engineSetCertificateEntry(String alias, Certificate cert)
          throws KeyStoreException {
    // TODO Auto-generated method stub

  }

  @Override
  public void engineDeleteEntry(String alias) throws KeyStoreException {
    // TODO Auto-generated method stub

  }

  @Override
  public Enumeration<String> engineAliases() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public boolean engineContainsAlias(String alias) {
    // TODO Auto-generated method stub
    return false;
  }

  @Override
  public int engineSize() {
    // TODO Auto-generated method stub
    return 0;
  }

  @Override
  public boolean engineIsKeyEntry(String alias) {
    // TODO Auto-generated method stub
    return false;
  }

  @Override
  public boolean engineIsCertificateEntry(String alias) {
    // TODO Auto-generated method stub
    return false;
  }

  @Override
  public String engineGetCertificateAlias(Certificate cert) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public void engineStore(OutputStream stream, char[] password)
          throws IOException, NoSuchAlgorithmException, CertificateException {
    // TODO Auto-generated method stub

  }

  @Override
  public void engineLoad(InputStream stream, char[] password)
          throws IOException, NoSuchAlgorithmException, CertificateException {
    // TODO Auto-generated method stub
  }

  @Override
  public void engineLoad(LoadStoreParameter param)
          throws IOException, NoSuchAlgorithmException, CertificateException {
    // TODO Auto-generated method stub
    super.engineLoad(param);
  }

}
