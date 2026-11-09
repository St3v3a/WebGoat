/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint-mitigation-13-1",
      "SqlStringInjectionHint-mitigation-13-2",
      "SqlStringInjectionHint-mitigation-13-3",
      "SqlStringInjectionHint-mitigation-13-4"
    })
public class SqlInjectionLesson13 implements AssignmentEndpoint {

  private final SortMitigationProgress progress;

  public SqlInjectionLesson13(SortMitigationProgress progress) {
    this.progress = progress;
  }

  @PostMapping("/SqlInjectionMitigations/attack12a")
  @ResponseBody
  public AttackResult completed(@RequestParam(required = false) String safeColumn) {
    if (!progress.completedWith(safeColumn)) {
      return failed(this).build();
    }
    return success(this).build();
  }
}
