/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/** Replaces the publicly seeded lesson password once in each user's lesson schema. */
final class DaveLessonCredential {
  private static final String PUBLIC_SEED = "passW0rD";
  private static final String USER_NAME = "dave";
  private static final char[] ALPHABET =
      "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789".toCharArray();
  private static final SecureRandom RANDOM = new SecureRandom();

  private DaveLessonCredential() {}

  static String current(Connection connection) throws SQLException {
    try (PreparedStatement rotate =
        connection.prepareStatement(
            "UPDATE user_system_data SET password = ? WHERE user_name = ? AND password = ?")) {
      rotate.setString(1, randomPassword());
      rotate.setString(2, USER_NAME);
      rotate.setString(3, PUBLIC_SEED);
      if (rotate.executeUpdate() == 1 && !connection.getAutoCommit()) {
        connection.commit();
      }
    }

    try (PreparedStatement read =
        connection.prepareStatement("SELECT password FROM user_system_data WHERE user_name = ?")) {
      read.setString(1, USER_NAME);
      try (ResultSet result = read.executeQuery()) {
        if (result.next()) {
          String value = result.getString(1);
          if (value != null && !value.isBlank() && !PUBLIC_SEED.equals(value)) {
            return value;
          }
        }
      }
    }
    throw new SQLException("Dave's lesson credential is unavailable");
  }

  private static String randomPassword() {
    char[] password = new char[10];
    String candidate;
    do {
      for (int i = 0; i < password.length; i++) {
        password[i] = ALPHABET[RANDOM.nextInt(ALPHABET.length)];
      }
      candidate = new String(password);
    } while (PUBLIC_SEED.equals(candidate));
    return candidate;
  }
}
