/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class EncDec {

  private static final byte[] KEY = new byte[32];
  private static final String PREFIX = "v1:";
  private static final int MAC_LENGTH = 32;

  static {
    new SecureRandom().nextBytes(KEY);
  }

  private EncDec() {}

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }
    byte[] message = (PREFIX + value.toLowerCase(Locale.ROOT)).getBytes(StandardCharsets.UTF_8);
    byte[] signature = sign(message);
    byte[] cookie = Arrays.copyOf(message, message.length + signature.length);
    System.arraycopy(signature, 0, cookie, message.length, signature.length);
    return Base64.getEncoder().encodeToString(cookie);
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }
    byte[] cookie = Base64.getDecoder().decode(encodedValue);
    if (cookie.length <= PREFIX.length() + MAC_LENGTH || cookie.length > 512) {
      throw new IllegalArgumentException("Invalid authentication cookie");
    }
    int messageLength = cookie.length - MAC_LENGTH;
    byte[] message = Arrays.copyOf(cookie, messageLength);
    byte[] signature = Arrays.copyOfRange(cookie, messageLength, cookie.length);
    if (!MessageDigest.isEqual(sign(message), signature)) {
      throw new IllegalArgumentException("Invalid authentication cookie");
    }
    String value = new String(message, StandardCharsets.UTF_8);
    if (!value.startsWith(PREFIX) || value.length() == PREFIX.length()) {
      throw new IllegalArgumentException("Invalid authentication cookie");
    }
    return value.substring(PREFIX.length());
  }

  private static byte[] sign(byte[] message) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
      return mac.doFinal(message);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Authentication cookie signing is unavailable", e);
    }
  }
}
