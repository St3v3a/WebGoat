/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.SessionScope;

/** One-use demo credentials that have no authority outside the issuing lesson session. */
@Component
@SessionScope
public class InsecureLoginDemoState {
  private static final String DEMO_USER = "CaptainJack";
  private static final long VALID_FOR_MILLIS = 5 * 60 * 1000L;
  private static final SecureRandom RANDOM = new SecureRandom();

  private byte[] passwordDigest;
  private long expiresAt;
  private boolean loginRequestSeen;

  public synchronized Map<String, String> issue() {
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    String password = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    passwordDigest = digest(password);
    expiresAt = System.currentTimeMillis() + VALID_FOR_MILLIS;
    loginRequestSeen = false;
    return Map.of("username", DEMO_USER, "password", password);
  }

  public synchronized boolean recordLogin(String username, String password) {
    if (!matches(username, password)) {
      return false;
    }
    loginRequestSeen = true;
    return true;
  }

  public synchronized boolean consume(String username, String password) {
    if (!loginRequestSeen || !matches(username, password)) {
      return false;
    }
    passwordDigest = null;
    loginRequestSeen = false;
    expiresAt = 0;
    return true;
  }

  private boolean matches(String username, String password) {
    if (passwordDigest == null
        || System.currentTimeMillis() > expiresAt
        || !DEMO_USER.equals(username)
        || password == null) {
      return false;
    }
    return MessageDigest.isEqual(passwordDigest, digest(password));
  }

  private static byte[] digest(String value) {
    try {
      return MessageDigest.getInstance("SHA-256")
          .digest(value.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is unavailable", e);
    }
  }
}
