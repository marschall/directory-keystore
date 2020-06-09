package com.github.marschall.directorykeystore;

import java.util.Arrays;
import java.util.Objects;

final class Oid {

  // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnap/ff1a8675-0008-408c-ba5f-686a10389adc
  static final Oid RSA = Oid.valueOf("1.2.840.113549.1.1.1");
  static final Oid DSA = Oid.valueOf("1.2.840.10040.4.1");
  static final Oid DH = Oid.valueOf("1.2.840.10046.2.1");
//  private static final Oid DSA = Oid.valueOf("1.3.14.3.2.12");
//  private static final Oid DH = Oid.valueOf("1.2.840.113549.1.3.1");
  static final Oid ECDSA_P256 = Oid.valueOf("1.2.840.10045.3.1.7");
  static final Oid ECDSA_P384 = Oid.valueOf("1.3.132.0.34");
  static final Oid ECDSA_P521 = Oid.valueOf("1.3.132.0.35");

  private final int[] nodes;

  Oid(int... nodes) {
    Objects.requireNonNull(nodes, "nodes");
    this.nodes = nodes;
  }

  static Oid valueOf(String s) {
    return new Oid(Arrays.stream(s.split("\\.")).mapToInt(Integer::parseInt).toArray());
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!(obj instanceof Oid)) {
      return false;
    }
    Oid other = (Oid) obj;
    return Arrays.equals(this.nodes, other.nodes);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(this.nodes);
  }

  @Override
  public String toString() {
    StringBuilder buffer = new StringBuilder();
    for (int i = 0; i < this.nodes.length; i++) {
      if (i > 0) {
        buffer.append('.');
      }
      buffer.append(this.nodes[i]);
    }
    return buffer.toString();
  }

}