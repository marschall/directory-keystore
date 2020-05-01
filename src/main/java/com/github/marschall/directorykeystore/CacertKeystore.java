package com.github.marschall.directorykeystore;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

final class CacertKeystore extends KeyStoreSpi {

  private List<Certificate> certificates;

  @Override
  public Key engineGetKey(String alias, char[] password)
          throws NoSuchAlgorithmException, UnrecoverableKeyException {
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
    return this.certificates.size();
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
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    this.certificates = new ArrayList<>(factory.generateCertificates(stream));
  }

}
