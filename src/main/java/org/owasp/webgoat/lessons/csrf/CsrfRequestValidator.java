/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;

/** Checks the browser-controlled Origin header before a CSRF lesson changes session state. */
final class CsrfRequestValidator {

  private CsrfRequestValidator() {}

  static boolean isSameOrigin(HttpServletRequest request) {
    String originHeader = request.getHeader("Origin");
    if (originHeader == null) {
      return false;
    }

    try {
      URI origin = URI.create(originHeader);
      String scheme = origin.getScheme();
      if (origin.isOpaque()
          || origin.getHost() == null
          || scheme == null
          || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))
          || origin.getRawUserInfo() != null
          || (origin.getRawPath() != null && !origin.getRawPath().isEmpty())
          || origin.getRawQuery() != null
          || origin.getRawFragment() != null) {
        return false;
      }

      int originPort =
          origin.getPort() == -1 ? (scheme.equalsIgnoreCase("https") ? 443 : 80) : origin.getPort();
      return scheme.equalsIgnoreCase(request.getScheme())
          && origin.getHost().equalsIgnoreCase(request.getServerName())
          && originPort == request.getServerPort();
    } catch (IllegalArgumentException e) {
      return false;
    }
  }
}
