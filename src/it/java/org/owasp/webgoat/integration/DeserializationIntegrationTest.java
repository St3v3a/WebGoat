/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.integration;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.dummy.insecure.framework.VulnerableTaskHolder;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.lessons.deserialization.SerializationHelper;

public class DeserializationIntegrationTest extends IntegrationTest {

  @Test
  public void runTests() throws IOException {
    startLesson("InsecureDeserialization");

    Map<String, Object> params = new HashMap<>();
    params.clear();

    params.put("token", SerializationHelper.toString(new VulnerableTaskHolder("wait", "sleep 5")));
      checkAssignment(webGoatUrlConfig.url("InsecureDeserialization/task"), params, false);
  }
}
