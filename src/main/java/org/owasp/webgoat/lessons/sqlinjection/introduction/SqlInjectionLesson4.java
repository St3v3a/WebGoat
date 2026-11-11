/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
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

/**
 * Data Definition Language exercise.
 *
 * <p>The endpoint used to pass the caller's text straight to {@code Statement.executeUpdate},
 * which allowed any schema change. Identifiers cannot be bound, so the learner now picks the
 * operation, column and type from fixed lists and the server emits the statement itself.
 */
@RestController
@AssignmentHints(
    value = {"SqlStringInjectionHint4-1", "SqlStringInjectionHint4-2", "SqlStringInjectionHint4-3"})
public class SqlInjectionLesson4 implements AssignmentEndpoint {

  private static final Set<String> OPERATIONS = Set.of("add", "drop");
  private static final Set<String> COLUMNS = Set.of("phone");
  private static final Set<String> TYPES = Set.of("varchar(20)", "int");

  private final LessonDataSource dataSource;

  public SqlInjectionLesson4(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack4")
  @ResponseBody
  public AttackResult completed(
      @RequestParam(required = false) String operation,
      @RequestParam(required = false) String column,
      @RequestParam(required = false) String type) {
    if (operation == null || column == null || type == null) {
      return failed(this).feedback("sql-injection.console.freeform").build();
    }
    String op = operation.trim().toLowerCase(Locale.ROOT);
    String name = column.trim().toLowerCase(Locale.ROOT);
    String dataType = type.trim().toLowerCase(Locale.ROOT);
    if (!OPERATIONS.contains(op) || !COLUMNS.contains(name) || !TYPES.contains(dataType)) {
      return failed(this).feedback("sql-injection.console.identifier").build();
    }
    String sql =
        "add".equals(op)
            ? "ALTER TABLE employees ADD " + name + " " + dataType
            : "ALTER TABLE employees DROP COLUMN " + name;
    return alter(sql);
  }

  private AttackResult alter(String sql) {
    try (Connection connection = dataSource.getConnection();
        Statement statement = connection.createStatement()) {
      try {
        statement.executeUpdate(sql);
        connection.commit();
      } catch (SQLException alreadyApplied) {
        // adding an existing column or dropping a missing one changes nothing
      }
      // user completes lesson if column phone exists
      try (ResultSet results = statement.executeQuery("SELECT phone FROM employees")) {
        results.next();
        return success(this).output("<span class='feedback-positive'>" + sql + "</span>").build();
      } catch (SQLException noSuchColumn) {
        return failed(this).output(sql).build();
      }
    } catch (SQLException sqle) {
      return failed(this).feedback("sql-injection.console.failed").build();
    }
  }
}
