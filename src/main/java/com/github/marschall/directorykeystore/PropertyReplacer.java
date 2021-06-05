package com.github.marschall.directorykeystore;

import java.util.Properties;

final class PropertyReplacer {

  private PropertyReplacer() {
    throw new AssertionError("not instantiable");
  }

  static String replaceProperties(String s) {
    return replaceProperties(s, System.getProperties());
  }

  static String replaceProperties(String s, Properties properties) {
    int firstPropertIndex = s.indexOf("${");
    if (firstPropertIndex != -1) {
      return replaceProperties(s, properties, firstPropertIndex);
    } else {
      return s;
    }
  }

  private static String replaceProperties(String s, Properties properties, int firstPropertIndex) {
    int propertyStart = firstPropertIndex;
    int propertyEnd = s.indexOf('}', propertyStart + 2);
    if (propertyEnd != -1) {
      StringBuilder buffer = new StringBuilder(s.length());
      buffer.append(s, 0, propertyStart);

      replaceInto(s, propertyStart, propertyEnd, buffer, properties);

      propertyStart = s.indexOf("${", propertyEnd);
      while (propertyStart != -1) {
        int newEnd = s.indexOf('}', propertyStart + 2);
        if (newEnd == -1) {
          break;
        }
        buffer.append(s, propertyEnd + 1, propertyStart);
        propertyEnd = newEnd;
        replaceInto(s, propertyStart, propertyEnd, buffer, properties);
        propertyStart = s.indexOf("${", propertyEnd);
      }
      buffer.append(s, propertyEnd + 1, s.length());

      return buffer.toString();
    } else {
      return s;
    }
  }

  private static void replaceInto(String s, int start, int end, StringBuilder buffer, Properties properties) {
    String propertyName = s.substring(start + 2, end);
    String propertyValue = properties.getProperty(propertyName);
    buffer.append(propertyValue);
  }

}
