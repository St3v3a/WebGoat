/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

class LogSpoofingTaskTest {

  private final LogSpoofingTask task = new LogSpoofingTask();

  @Test
  void keepsFailedLoginOutputOnOneSafeLine() {
    for (String username : new String[] {"5\nLogin Succeeded for username admin", "5\r\nadmin", "admin", "<br/>admin", "<script>alert(1)</script>"}) {
      var result = task.completed(username, "ignored");
      assertFalse(result.assignmentSolved());
      assertFalse(result.getOutput().contains("\n"));
      assertFalse(result.getOutput().contains("\r"));
      assertFalse(result.getOutput().contains("<"));
    }
    assertEquals("alice", task.completed("alice", "ignored").getOutput());
  }
}
