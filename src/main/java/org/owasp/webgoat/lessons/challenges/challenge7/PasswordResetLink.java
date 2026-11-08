/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * @author nbaars
 * @since 8/17/17.
 */
public class PasswordResetLink {

  private static final SecureRandom RANDOM = new SecureRandom();

  public String createPasswordReset(String username, String key) {
    byte[] token = new byte[32];
    RANDOM.nextBytes(token);
    return HexFormat.of().formatHex(token);
  }

  public static void main(String[] args) {
    if (args == null || args.length != 2) {
      System.out.println("Need a username and key");
      System.exit(1);
    }
    String username = args[0];
    String key = args[1];
    System.out.println("Generation password reset link for " + username);
    System.out.println(
        "Created password reset link: "
            + new PasswordResetLink().createPasswordReset(username, key));
  }
}
