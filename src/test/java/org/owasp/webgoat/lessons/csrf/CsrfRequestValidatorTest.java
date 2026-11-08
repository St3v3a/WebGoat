/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class CsrfRequestValidatorTest {

  private MockHttpServletRequest request(String origin) {
    var request = new MockHttpServletRequest();
    request.setScheme("http");
    request.setServerName("webgoat.example");
    request.setServerPort(8080);
    if (origin != null) {
      request.addHeader("Origin", origin);
    }
    return request;
  }

  @Test
  void allowsOnlyTheExactOrigin() {
    assertTrue(CsrfRequestValidator.isSameOrigin(request("http://webgoat.example:8080")));
    assertFalse(CsrfRequestValidator.isSameOrigin(request(null)));
    assertFalse(CsrfRequestValidator.isSameOrigin(request("null")));
    assertFalse(CsrfRequestValidator.isSameOrigin(request("http://evil.example:8080")));
    assertFalse(CsrfRequestValidator.isSameOrigin(request("http://webgoat.example.evil:8080")));
    assertFalse(CsrfRequestValidator.isSameOrigin(request("https://webgoat.example:8080")));
    assertFalse(CsrfRequestValidator.isSameOrigin(request("http://webgoat.example")));
    assertFalse(CsrfRequestValidator.isSameOrigin(request("http://webgoat.example:8080/path")));
    assertFalse(CsrfRequestValidator.isSameOrigin(request("http://webgoat.example:8080@evil")));
  }
}
