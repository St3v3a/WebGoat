/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.security.core.Authentication;

final class MissingFunctionACAuthorization {

  private MissingFunctionACAuthorization() {}

  static boolean isAdmin(Authentication authentication) {
    return authentication != null
        && authentication.isAuthenticated()
        && authentication.getAuthorities().stream()
            .anyMatch(authority -> WebGoatUser.ROLE_ADMIN.equals(authority.getAuthority()));
  }
}
