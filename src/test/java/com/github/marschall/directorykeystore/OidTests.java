package com.github.marschall.directorykeystore;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class OidTests {

  @Test
  void rsa() {
    assertEquals("1.2.840.113549.1.1.1", Oid.RSA.toString());
    assertEquals(Oid.RSA, Oid.valueOf("1.2.840.113549.1.1.1"));
  }

}
