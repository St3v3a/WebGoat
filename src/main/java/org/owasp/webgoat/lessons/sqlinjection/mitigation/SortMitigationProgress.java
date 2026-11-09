/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.SessionScope;

/** Tracks the safe-sort exercise for one learner session. */
@Component
@SessionScope
public class SortMitigationProgress {
  private boolean rejectedExpression;
  private String lastSuccessfulColumn;

  static String trustedColumn(String column) {
    if (column == null) {
      throw new IllegalArgumentException("Missing sort column");
    }
    return switch (column) {
      case "id" -> "id";
      case "hostname" -> "hostname";
      case "ip" -> "ip";
      case "mac" -> "mac";
      case "status" -> "status";
      case "description" -> "description";
      default -> throw new IllegalArgumentException("Invalid sort column");
    };
  }

  synchronized void recordRejectedExpression() {
    rejectedExpression = true;
    lastSuccessfulColumn = null;
  }

  synchronized void recordSuccessfulSort(String column) {
    lastSuccessfulColumn = column;
  }

  synchronized boolean completedWith(String column) {
    return rejectedExpression && column != null && column.equals(lastSuccessfulColumn);
  }
}
