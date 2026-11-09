/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.web.client.RestTemplate;

class SimpleMailAssignmentTest {

  @Test
  void resetPasswordIsDeliveredAndSingleUse() {
    RestTemplate mailer = mock(RestTemplate.class);
    SimpleMailAssignment assignment =
        new SimpleMailAssignment(mailer, "http://webwolf/mail");

    assertFalse(assignment.login("webgoat@webgoat.org", "taogbew", "webgoat").isLessonCompleted());
    assignment.resetPassword("webgoat@webgoat.org", "webgoat");

    ArgumentCaptor<PasswordResetEmail> mail = ArgumentCaptor.forClass(PasswordResetEmail.class);
    verify(mailer).postForEntity(eq("http://webwolf/mail"), mail.capture(), eq(Object.class));
    String delivered = mail.getValue().getContents();
    String password = delivered.substring(delivered.lastIndexOf(": ") + 2);
    assertNotEquals("taogbew", password);
    assertTrue(password.length() >= 32);
    assertTrue(assignment.login("webgoat@webgoat.org", password, "webgoat").isLessonCompleted());
    assertFalse(assignment.login("webgoat@webgoat.org", password, "webgoat").isLessonCompleted());
  }
}
