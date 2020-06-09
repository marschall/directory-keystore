package com.github.marschall.directorykeystore;

import java.util.Arrays;

final class TagType {

  /**
   * The contents octets directly encode the element value.
   */
  static final int VALUE_ENCODING_PRIMITIVE = 0;

  /**
   * The contents octets contain 0, 1, or more element encodings.
   */
  static final int VALUE_ENCODING_CONSTRUCTED = 1;

  /**
   *  The type is native to ASN.1
   */
  static final int TAG_CLASS_UNIVERSAL = 0;

 /**
  * The type is only valid for one specific application
  */
  static final int TAG_CLASS_APPLICATION = 1;

  /**
   * Meaning of this type depends on the context (such as within a sequence, set or choice)
   */
  static final int TAG_CLASS_CONTEXT_SPECIFIC = 2;

  /**
   * Defined in private specifications
   */
  static final int TAG_CLASS_PRIVATE = 3;

  static TagType SEQUENCE = new TagType(TAG_CLASS_UNIVERSAL, VALUE_ENCODING_CONSTRUCTED, 0x10);

  static TagType INTEGER = new TagType(TAG_CLASS_UNIVERSAL, VALUE_ENCODING_PRIMITIVE, 0x02);

  static TagType NULL = new TagType(TAG_CLASS_UNIVERSAL, VALUE_ENCODING_PRIMITIVE, 0x05);

  static TagType OBJECT_IDENTIFIER = new TagType(TAG_CLASS_UNIVERSAL, VALUE_ENCODING_PRIMITIVE, 0x06);

  static TagType RELATIVE_OID  = new TagType(TAG_CLASS_UNIVERSAL, VALUE_ENCODING_PRIMITIVE, 0x0D);

  private final byte tagClass;
  private final byte valueEncoding;
  private final int tagNumber;

  TagType(int tagClass, int valueEncoding, int tagNumber) {
    if (tagClass > Byte.MAX_VALUE) {
      throw new IllegalArgumentException("tagClass value too large");
    }
    if (valueEncoding > Byte.MAX_VALUE) {
      throw new IllegalArgumentException("valueEncoding value too large");
    }
    this.tagClass = (byte) tagClass;
    this.valueEncoding = (byte) valueEncoding;
    this.tagNumber = tagNumber;
  }

  int getTagClass() {
    return this.tagClass;
  }

  int getValueEncoding() {
    return this.valueEncoding;
  }

  int getTagNumber() {
    return this.tagNumber;
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(new int[] {this.tagClass, this.tagNumber, this.valueEncoding});
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof TagType)) {
      return false;
    }
    TagType other = (TagType) obj;
    return (this.tagClass == other.tagClass)
            && (this.tagNumber == other.tagNumber)
            && (this.valueEncoding == other.valueEncoding);
  }



}