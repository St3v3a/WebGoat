/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.authbypass;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.mock.web.MockHttpServletRequest;

class BypassVerificationTest {

  private final LessonSession lessonSession = mock(LessonSession.class);
  private final VerifyAccount endpoint = new VerifyAccount(lessonSession);

  private MockHttpServletRequest correctAnswers() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("secQuestion0", "Dr. Watson");
    request.addParameter("secQuestion1", "Baker Street");
    return request;
  }

  @Test
  void correctAnswersVerifyTheSeededAccount() throws Exception {
    assertTrue(endpoint.completed("1223445", "SEC_QUESTIONS", correctAnswers()).assignmentSolved());
    verify(lessonSession).setValue("account-verified-id", "1223445");
  }

  @Test
  void unrelatedQuestionsDoNotVerifyTheAccount() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("secQuestion2", "any");
    request.addParameter("secQuestion3", "any");
    assertFalse(endpoint.completed("1223445", "SEC_QUESTIONS", request).assignmentSolved());
  }

  @Test
  void duplicateAndRenamedQuestionsAreRejected() throws Exception {
    MockHttpServletRequest duplicate = correctAnswers();
    duplicate.addParameter("secQuestion0", "another");
    assertFalse(endpoint.completed("1223445", "SEC_QUESTIONS", duplicate).assignmentSolved());

    MockHttpServletRequest renamed = correctAnswers();
    renamed.addParameter("notsecQuestion0", "anything");
    assertFalse(endpoint.completed("1223445", "SEC_QUESTIONS", renamed).assignmentSolved());
  }

  @Test
  void accountAndMethodMustMatch() throws Exception {
    assertFalse(endpoint.completed("12309746", "SEC_QUESTIONS", correctAnswers()).assignmentSolved());
    assertFalse(endpoint.completed("1223445", "OTHER", correctAnswers()).assignmentSolved());
    assertFalse(endpoint.completed("not-an-id", "SEC_QUESTIONS", correctAnswers()).assignmentSolved());
  }
}
