/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.integration;

import io.restassured.http.ContentType;
import org.junit.jupiter.api.Test;

public class XXEIntegrationTest extends IntegrationTest {

  private static final String EXTERNAL_ENTITY =
      "<?xml version=\"1.0\"?><!DOCTYPE comment [<!ENTITY xxe SYSTEM \"file:///\">]>"
          + "<comment><text>&xxe;</text></comment>";

  @Test
  public void rejectsExternalEntities() {
    startLesson("XXE");
    checkAssignment(webGoatUrlConfig.url("xxe/simple"), ContentType.XML, EXTERNAL_ENTITY, false);
    checkAssignment(
        webGoatUrlConfig.url("xxe/content-type"), ContentType.XML, EXTERNAL_ENTITY, false);
    checkAssignment(webGoatUrlConfig.url("xxe/blind"), ContentType.XML, EXTERNAL_ENTITY, false);
  }
}
