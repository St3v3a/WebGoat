/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.bypassrestrictions;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class BypassRestrictionsFieldRestrictionsTest {

  private final BypassRestrictionsFieldRestrictions assignment =
      new BypassRestrictionsFieldRestrictions();

  @Test
  void acceptsOnlyValuesAvailableInTheForm() {
    assertTrue(assignment.completed("option1", "option2", "on", "12345", "change").isLessonCompleted());
    assertFalse(assignment.completed("option3", "option3", "maybe", "longer", "hacked").isLessonCompleted());
    assertFalse(assignment.completed("option1", "option2", "on", "123456", "change").isLessonCompleted());
  }
}
