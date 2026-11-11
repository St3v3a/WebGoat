/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.idorDiffAttributes1",
  "idor.hints.idorDiffAttributes2",
  "idor.hints.idorDiffAttributes3"
})
public class IDORDiffAttributes implements AssignmentEndpoint {

  private final LessonSession lessonSession;

  public IDORDiffAttributes(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  @PostMapping("/IDOR/diff-attributes")
  @ResponseBody
  public AttackResult completed(@RequestParam String attributes) {
    // The profile whose attributes are compared is only served to a learner who signed in.
    if (!"tom".equals(lessonSession.getValue("idor-authenticated-as"))) {
      return failed(this).feedback("idor.view.own.profile.failure2").build();
    }
    attributes = attributes.trim();
    String[] diffAttribs = attributes.split(",");
    if (diffAttribs.length < 2) {
      return failed(this).feedback("idor.diff.attributes.missing").build();
    }
    if (diffAttribs[0].toLowerCase().trim().equals("userid")
            && diffAttribs[1].toLowerCase().trim().equals("role")
        || diffAttribs[1].toLowerCase().trim().equals("userid")
            && diffAttribs[0].toLowerCase().trim().equals("role")) {
      return success(this).feedback("idor.diff.success").build();
    } else {
      return failed(this).feedback("idor.diff.failure").build();
    }
  }
}
