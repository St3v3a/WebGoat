/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 1/5/17. */
@RestController
@AssignmentHints({
  "access-control.hidden-menus.hint1",
  "access-control.hidden-menus.hint2",
  "access-control.hidden-menus.hint3"
})
public class MissingFunctionACHiddenMenus implements AssignmentEndpoint {

  @PostMapping(
      path = "/access-control/hidden-menu",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(String hiddenMenu1, String hiddenMenu2) {
    // The administrator entries used to be delivered to every user and hidden with CSS. They are
    // no longer part of the page a regular user receives, so the former labels are not an answer.
    if (isNone(hiddenMenu1) && isNone(hiddenMenu2)) {
      return success(this).output("").feedback("access-control.hidden-menus.success").build();
    }

    if (isFormerAdminEntry(hiddenMenu1) || isFormerAdminEntry(hiddenMenu2)) {
      return failed(this).output("").feedback("access-control.hidden-menus.close").build();
    }

    return failed(this).feedback("access-control.hidden-menus.failure").output("").build();
  }

  private static boolean isNone(String value) {
    return value != null && "none".equalsIgnoreCase(value.trim());
  }

  private static boolean isFormerAdminEntry(String value) {
    return value != null
        && ("users".equalsIgnoreCase(value.trim()) || "config".equalsIgnoreCase(value.trim()));
  }
}
