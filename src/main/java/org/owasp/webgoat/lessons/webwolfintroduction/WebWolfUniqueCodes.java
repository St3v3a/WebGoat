/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Issues the code a learner has to read back from WebWolf.
 *
 * <p>The code used to be the reversed username, so anyone who knew a username could complete the
 * exercises without ever receiving the mail or the landing request. Each user now gets an
 * unpredictable value that is only delivered through WebWolf.
 */
public final class WebWolfUniqueCodes {

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final ConcurrentMap<String, String> CODES = new ConcurrentHashMap<>();

  private WebWolfUniqueCodes() {}

  /** Returns the code for this user, creating it on first use. */
  public static String forUser(String username) {
    return CODES.computeIfAbsent(String.valueOf(username), WebWolfUniqueCodes::newCode);
  }

  /** Compares a submitted code with the one issued to this user in constant time. */
  public static boolean matches(String username, String submitted) {
    if (submitted == null) {
      return false;
    }
    return MessageDigest.isEqual(
        forUser(username).getBytes(StandardCharsets.UTF_8),
        submitted.trim().getBytes(StandardCharsets.UTF_8));
  }

  private static String newCode(String username) {
    byte[] bytes = new byte[12];
    RANDOM.nextBytes(bytes);
    return HexFormat.of().formatHex(bytes);
  }
}
