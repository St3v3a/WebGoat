/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;
import java.util.Set;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

/**
 * Data Manipulation Language exercise.
 *
 * <p>The endpoint used to pass the caller's text straight to {@code Statement.executeUpdate}. The
 * learner now composes one UPDATE of the department column from allow-listed identifiers and
 * bound values; no caller text becomes SQL.
 */
@RestController
@AssignmentHints(value = {"SqlStringInjectionHint3-1", "SqlStringInjectionHint3-2"})
public class SqlInjectionLesson3 implements AssignmentEndpoint {

  private static final Set<String> UPDATABLE = Set.of("department");
  private static final Set<String> FILTERABLE = Set.of("first_name", "last_name");
  private static final int MAX_VALUE_LENGTH = 20;

  private final LessonDataSource dataSource;

  public SqlInjectionLesson3(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack3")
  @ResponseBody
  public AttackResult completed(
      @RequestParam(required = false) String column,
      @RequestParam(required = false) String newValue,
      @RequestParam(required = false) String filterColumn,
      @RequestParam(required = false) String value) {
    if (column == null || newValue == null || filterColumn == null || value == null) {
      return failed(this).feedback("sql-injection.console.freeform").build();
    }
    String target = column.trim().toLowerCase(Locale.ROOT);
    String filter = filterColumn.trim().toLowerCase(Locale.ROOT);
    if (!UPDATABLE.contains(target) || !FILTERABLE.contains(filter)) {
      return failed(this).feedback("sql-injection.console.identifier").build();
    }
    if (newValue.isBlank() || newValue.length() > MAX_VALUE_LENGTH) {
      return failed(this).feedback("sql-injection.console.value").build();
    }
    return update(target, newValue, filter, value);
  }

  private AttackResult update(String target, String newValue, String filter, String value) {
    String sql = "UPDATE employees SET " + target + " = ? WHERE " + filter + " = ?";
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement(sql);
        PreparedStatement check =
            connection.prepareStatement(
                "SELECT * FROM employees WHERE last_name = ?",
                TYPE_SCROLL_INSENSITIVE,
                CONCUR_READ_ONLY)) {
      statement.setString(1, newValue);
      statement.setString(2, value);
      statement.executeUpdate();
      check.setString(1, "Barnett");
      ResultSet results = check.executeQuery();
      StringBuilder output = new StringBuilder();
      // user completes lesson if the department of Tobi Barnett now is 'Sales'
      if (results.first() && "Sales".equals(results.getString("department"))) {
        output.append("<span class='feedback-positive'>");
        output.append(HtmlUtils.htmlEscape(sql + "  [? = " + newValue + ", ? = " + value + "]"));
        output.append("</span>");
        output.append(SqlInjectionLesson8.generateTable(results));
        return success(this).output(output.toString()).build();
      }
      return failed(this).output(output.toString()).build();
    } catch (SQLException sqle) {
      return failed(this).feedback("sql-injection.console.failed").build();
    }
  }
}
