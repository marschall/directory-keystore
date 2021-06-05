package com.github.marschall.directorykeystore;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Properties;

import org.junit.jupiter.api.Test;

class PropertyReplacerTests {

  @Test
  void replaceProperties() {
    String s = "${user.dir}/src/test/resources/keystores/sample-${java.version}.dks#junit_protected";
    Properties properties = new Properties();
    properties.put("user.dir", "/home/user/git/system-dks-keystore");
    properties.put("java.version", "11");

    assertEquals("/home/user/git/system-dks-keystore/src/test/resources/keystores/sample-11.dks#junit_protected", PropertyReplacer.replaceProperties(s, properties));
  }

  @Test
  void replacePropertiesUnmatchedParenthesis() {
    String s = "${user.dir/src/test/resources/keystores/sample-${java.version.dks#junit_protected";
    Properties properties = new Properties();
    properties.put("user.dir", "/home/user/git/system-dks-keystore");
    properties.put("java.version", "11");

    assertEquals("${user.dir/src/test/resources/keystores/sample-${java.version.dks#junit_protected", PropertyReplacer.replaceProperties(s, properties));
  }

  @Test
  void replacePropertiesSingleProperty() {
    String s = "${user.dir}";
    Properties properties = new Properties();
    properties.put("user.dir", "/home/user/git/system-dks-keystore");
    properties.put("java.version", "11");

    assertEquals("/home/user/git/system-dks-keystore", PropertyReplacer.replaceProperties(s, properties));
  }

  @Test
  void replacePropertiesNoPlacehodlder() {
    String s = "/home/user/git/system-dks-keystore/src/test/resources/keystores/sample-11.dks#junit_protected";
    Properties properties = new Properties();

    assertEquals("/home/user/git/system-dks-keystore/src/test/resources/keystores/sample-11.dks#junit_protected", PropertyReplacer.replaceProperties(s, properties));
  }

}
