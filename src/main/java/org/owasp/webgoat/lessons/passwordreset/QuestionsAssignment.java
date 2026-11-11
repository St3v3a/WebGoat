/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.util.Map;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class QuestionsAssignment implements AssignmentEndpoint {

  /**
   * Recovery by security question has been retired.
   *
   * <p>The form used to accept one of a handful of colours as proof of identity, with no limit on
   * attempts, so any account could be recovered by guessing. A knowledge-based answer is not an
   * acceptable recovery factor (NIST SP 800-63B), so no answer is accepted here any more and the
   * seeded answers have been removed. Recovery goes through the reset link sent to the registered
   * address.
   */
  @PostMapping(
      path = "/PasswordReset/questions",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public AttackResult passwordReset(@RequestParam Map<String, Object> json) {
    return failed(this).feedback("password-questions-retired").build();
  }
}
