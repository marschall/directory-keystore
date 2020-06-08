package com.github.marschall.directorykeystore;

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

    // oids https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnap/ff1a8675-0008-408c-ba5f-686a10389adc

    byte[] pkcs8 = loadKey(Paths.get("src/test/resources/sample-keystore/pkcs8/privateKey.key"));
    try (InputStream inputStream = new ByteArrayInputStream(pkcs8)) {
      int type = inputStream.read();
      int tagClass = (type & 0b11_00_00_00) >> 6;
      int valueEncoding = (type & 0b10_00_00) >> 5;
      int tagNumber = (type & 0b1_11_11);

      int lengthOctet1 = inputStream.read();
      if (lengthOctet1 == 0xFF) {
        // TODO reserved
      }
      if (lengthOctet1 == 0x80) {
        // TODO Indefinite
      }
      int length;
      boolean isShort = (lengthOctet1 & 0b10_00_00_00) == 1;
      if (isShort) {
        length = lengthOctet1 & 0b1_11_11_11;
      } else {
        int lengthOctetCount = lengthOctet1 & 0b1_11_11_11;
      }
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
