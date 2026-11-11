/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.web.client.RestTemplate;
import org.owasp.webgoat.lessons.passwordreset.resetlink.PasswordChangeForm;

class ResetLinkAssignmentForgotPasswordTest {

  @Test
  void untrustedHostCannotIssueOrLeakResetLink() {
    RestTemplate mailer = mock(RestTemplate.class);
    ResetLinkAssignmentForgotPassword assignment =
        new ResetLinkAssignmentForgotPassword(
            mailer,
            "localhost",
            "8080",
            "http://127.0.0.1:1/WebWolf",
            "http://webwolf/mail");
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("Host", "127.0.0.1:9090");
    int before = ResetLinkAssignment.resetLinks.size();

    assertFalse(assignment.sendPasswordResetLink(ResetLinkAssignment.TOM_EMAIL, request).isLessonCompleted());
    assertTrue(ResetLinkAssignment.resetLinks.size() == before);
    verifyNoInteractions(mailer);
  }

  @Test
  void trustedHostSendsMailWithConfiguredOrigin() {
    RestTemplate mailer = mock(RestTemplate.class);
    ResetLinkAssignmentForgotPassword assignment =
        new ResetLinkAssignmentForgotPassword(
            mailer,
            "localhost",
            "8080",
            "http://127.0.0.1:1/WebWolf",
            "http://webwolf/mail");
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("Host", "localhost:8080");

    assertTrue(assignment.sendPasswordResetLink("webgoat@webgoat.org", request).isLessonCompleted());
    ArgumentCaptor<PasswordResetEmail> mail = ArgumentCaptor.forClass(PasswordResetEmail.class);
    verify(mailer).postForEntity(eq("http://webwolf/mail"), mail.capture(), eq(Object.class));
    assertTrue(mail.getValue().getContents().contains("http://localhost:8080/WebGoat/"));
  }

  @Test
  void deliveredTomLinkCanChangePasswordOnce() {
    RestTemplate mailer = mock(RestTemplate.class);
    ResetLinkAssignmentForgotPassword assignment =
        new ResetLinkAssignmentForgotPassword(
            mailer,
            "localhost",
            "8080",
            "http://127.0.0.1:1/WebWolf",
            "http://webwolf/mail");
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("Host", "localhost:8080");
    assertTrue(assignment.sendPasswordResetLink(ResetLinkAssignment.TOM_EMAIL, request).isLessonCompleted());
    String link = ResetLinkAssignment.resetLinks.get(ResetLinkAssignment.resetLinks.size() - 1);

    PasswordChangeForm form = new PasswordChangeForm();
    form.setResetLink(link);
    form.setPassword("delivered-secret");
    var binding = new BeanPropertyBindingResult(form, "form");
    ResetLinkAssignment reset = new ResetLinkAssignment();
    assertTrue(reset.changePassword(form, binding, "testuser").getViewName().endsWith("success.html"));
    assertTrue(reset.login("delivered-secret", ResetLinkAssignment.TOM_EMAIL, "testuser").isLessonCompleted());
    assertFalse(ResetLinkAssignment.resetLinkToEmail.containsKey(link));
    assertTrue(reset.changePassword(form, binding, "testuser").getViewName().endsWith("password_link_not_found.html"));
  }
}
