/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

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
 * Data Query Language exercise.
 *
 * <p>The endpoint used to pass the caller's text straight to {@code Statement.executeQuery}, which
 * let any signed-in user run arbitrary SQL with the lesson connection's rights. The learner now
 * composes the SELECT from allow-listed identifiers and a bound value; no caller text becomes SQL.
 */
@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint2-1",
      "SqlStringInjectionHint2-2",
      "SqlStringInjectionHint2-3",
      "SqlStringInjectionHint2-4"
    })
public class SqlInjectionLesson2 implements AssignmentEndpoint {

  private static final Set<String> SELECTABLE =
      Set.of("userid", "first_name", "last_name", "department");
  private static final Set<String> FILTERABLE = Set.of("first_name", "last_name");

  private final LessonDataSource dataSource;

  public SqlInjectionLesson2(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack2")
  @ResponseBody
  public AttackResult completed(
      @RequestParam(required = false) String column,
      @RequestParam(required = false) String filterColumn,
      @RequestParam(required = false) String value) {
    if (column == null || filterColumn == null || value == null) {
      return failed(this).feedback("sql-injection.console.freeform").build();
    }
    String selected = column.trim().toLowerCase(Locale.ROOT);
    String filter = filterColumn.trim().toLowerCase(Locale.ROOT);
    if (!SELECTABLE.contains(selected) || !FILTERABLE.contains(filter)) {
      return failed(this).feedback("sql-injection.console.identifier").build();
    }
    return query(selected, filter, value);
  }

  private AttackResult query(String selected, String filter, String value) {
    String sql = "SELECT " + selected + " FROM employees WHERE " + filter + " = ?";
    try (var connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement(sql, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
      statement.setString(1, value);
      ResultSet results = statement.executeQuery();
      StringBuilder output = new StringBuilder();
      if (results.first()
          && "department".equals(selected)
          && "Marketing".equals(results.getString(1))) {
        output.append("<span class='feedback-positive'>");
        output.append(HtmlUtils.htmlEscape(sql + "  [? = " + value + "]"));
        output.append("</span>");
        output.append(SqlInjectionLesson8.generateTable(results));
        return success(this).feedback("sql-injection.2.success").output(output.toString()).build();
      }
      return failed(this).feedback("sql-injection.2.failed").output(output.toString()).build();
    } catch (SQLException sqle) {
      return failed(this).feedback("sql-injection.2.failed").build();
    }
  }
}
