/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class HtmlTamperingTaskTest {

  private final HtmlTamperingTask assignment = new HtmlTamperingTask();

  @Test
  void serverCalculatedTotalControlsCheckout() {
    assertTrue(assignment.completed("1", "2999.99").isLessonCompleted());
    assertTrue(assignment.completed("2", "5999.98").isLessonCompleted());
    assertFalse(assignment.completed("1", "0").isLessonCompleted());
    assertFalse(assignment.completed("1", "NaN").isLessonCompleted());
    assertFalse(assignment.completed("-1", "-2999.99").isLessonCompleted());
  }
}
