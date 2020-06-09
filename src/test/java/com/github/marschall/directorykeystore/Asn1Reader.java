package com.github.marschall.directorykeystore;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/**
 * A minimal ASN.1 reader for reading the key type of PKCS #8.
 */
final class Asn1Reader implements AutoCloseable {

  private final InputStream inputStream;

  Asn1Reader(InputStream inputStream) {
    Objects.requireNonNull(inputStream, "inputStream");
    this.inputStream = inputStream;
  }

  TagType readTagType() throws IOException {
    int type = this.inputStream.read();
    int tagClass = (type & 0b11_00_00_00) >> 6;
    int valueEncoding = (type & 0b10_00_00) >> 5;
    int tagNumber = (type & 0b1_11_11);
    return new TagType(tagClass, valueEncoding, tagNumber);
  }

  int readLength() throws IOException {
    // https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-integer
    int lengthOctet1 = this.inputStream.read();
    if (lengthOctet1 == 0xFF) {
      // TODO reserved
    }
    if (lengthOctet1 == 0x80) {
      // TODO Indefinite
    }
    boolean isShort = (lengthOctet1 & 0b10_00_00_00) == 0;
    if (isShort) {
      return lengthOctet1 & 0b1_11_11_11;
    } else {
      int lengthOctetCount = lengthOctet1 & 0b1_11_11_11;
      return this.readInteger(lengthOctetCount);
    }
  }

  int readInteger() throws IOException {
    int octetCount = this.readLength();
    return this.readInteger(octetCount);
  }

  private int readInteger(int octetCount) throws IOException {
    // TODO preserve high bit
    if (octetCount > 4) {
      throw new IllegalArgumentException("length too large");
    }
    if (octetCount == 0) {
      throw new IllegalArgumentException("zero length");
    }
    if (octetCount < 0) {
      throw new IllegalArgumentException("negative length");
    }
    int value = 0;
    for (int i = 0; i < octetCount; i++) {
      value = (value << 8) | this.inputStream.read();
    }
    return value;
  }

  Oid readOid() throws IOException {
    int length = this.readLength();
    if (length == 0) {
      throw new IllegalArgumentException("zero length");
    }
    IntList nodes = new IntList();

    int firstNodes = this.inputStream.read();
    int firstNode = firstNodes / 40;
    nodes.add(firstNode);
    int secondNode = firstNodes - (40 * firstNode);
    nodes.add(secondNode);

    return new Oid(nodes.toArray());
  }

  @Override
  public void close() throws IOException {
    this.inputStream.close();
  }


  static final class IntList {

    private int[] values;

    private int size;

    IntList() {
      this.values = new int[8];
      this.size = 0;
    }

    void add(int i) {
      if (this.size == this.values.length) {
        int[] newValues = new int[this.values.length * 2];
        System.arraycopy(this.values, 0, newValues, 0, this.values.length);
        this.values = newValues;
      }
      this.values[this.size++] = i;
    }

    int[] toArray() {
      int[] result = new int[this.size];
      System.arraycopy(this.values, 0, result, 0, this.size);
      return result;
    }

  }

}
