package com.github.marschall.directorykeystore;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import org.junit.jupiter.api.Test;

class LoadPrivateKeyTest {


  @Test
  void test() throws InvalidKeySpecException, IOException {
    // https://en.wikipedia.org/wiki/PKCS_8
    // https://lapo.it/asn1js/#MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAq7BFUpkGp3-LQmlQYx2eqzDV-xeG8kx_sQFV18S5JhzGeIJNA72wSeukEPojtqUyX2J0CciPBh7eqclQ2zpAswIDAQABAkAgisq4-zRdrzkwH1ITV1vpytnkO_NiHcnePQiOW0VUybPyHoGM_jf75C5xET7ZQpBe5kx5VHsPZj0CBb3b-wSRAiEA2mPWCBytosIU_ODRfq6EiV04lt6waE7I2uSPqIC20LcCIQDJQYIHQII-3YaPqyhGgqMexuuuGx-lDKD6_Fu_JwPb5QIhAKthiYcYKlL9h8bjDsQhZDUACPasjzdsDEdq8inDyLOFAiEAmCr_tZwA3qeAZoBzI10DGPIuoKXBd3nk_eBxPkaxlEECIQCNymjsoI7GldtujVnr1qT-3yedLfHKsrDVjIT3LsvTqw

    byte[] pkcs8 = loadKey(Paths.get("src/test/resources/sample-keystore/pkcs8/privateKey.key"));
    try (InputStream inputStream = new ByteArrayInputStream(pkcs8);
         Asn1Reader reader = new Asn1Reader(inputStream)) {

      TagType tagType = reader.readTagType();
      assertEquals(TagType.SEQUENCE, tagType);
      int sequenceLength = reader.readLength();
      assertEquals(342, sequenceLength);

      tagType = reader.readTagType();
      assertEquals(TagType.INTEGER, tagType);
      int version = reader.readInteger();
      assertEquals(0, version);

      tagType = reader.readTagType();
      assertEquals(TagType.SEQUENCE, tagType);
      sequenceLength = reader.readLength();
      assertEquals(13, sequenceLength);

      tagType = reader.readTagType();
      assertEquals(TagType.OBJECT_IDENTIFIER, tagType);
//      assertEquals(TagType.RELATIVE_OID, tagType);
      Oid oid = reader.readOid();
      assertEquals(Oid.RSA, oid);

      tagType = reader.readTagType();
      assertEquals(TagType.NULL, tagType);

      tagType = reader.readTagType();
    }

  }

  private static byte[] loadKey(Path keyFile) throws IOException, InvalidKeySpecException {
    try (InputStream inputStream = Files.newInputStream(keyFile);
         Reader reader = new InputStreamReader(inputStream, StandardCharsets.US_ASCII);
         BufferedReader buffered = new BufferedReader(reader, 1024)) {

      String begin = buffered.readLine();


      String line = buffered.readLine();
      StringBuilder base64Buffer = new StringBuilder();
      while ((line != null) && !line.startsWith("-----END ")) {
        base64Buffer.append(line);
        line = buffered.readLine();
      }

      return Base64.getMimeDecoder().decode(base64Buffer.toString());
    }
  }

}
