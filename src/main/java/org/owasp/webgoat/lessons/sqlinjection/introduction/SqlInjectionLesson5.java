/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.annotation.PostConstruct;
import java.sql.Connection;
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
 * Data Control Language exercise.
 *
 * <p>The endpoint used to pass the caller's text straight to {@code Statement.executeQuery}, so a
 * signed-in user could grant or revoke anything the lesson connection could. The learner now
 * picks the privilege, table and grantee from fixed lists and the server emits the statement.
 */
@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint5-1",
      "SqlStringInjectionHint5-2",
      "SqlStringInjectionHint5-3",
      "SqlStringInjectionHint5-4"
    })
public class SqlInjectionLesson5 implements AssignmentEndpoint {

  private static final Set<String> PRIVILEGES = Set.of("select", "insert", "update", "delete");
  private static final Set<String> TABLES = Set.of("grant_rights");
  private static final Set<String> GRANTEES = Set.of("unauthorized_user");

  private final LessonDataSource dataSource;

  public SqlInjectionLesson5(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostConstruct
  public void createUser() {
    // HSQLDB does not support CREATE USER with IF NOT EXISTS so we need to do it in code (using
    // DROP first will throw error if user does not exists)
    try (Connection connection = dataSource.getConnection()) {
      try (var statement =
          connection.prepareStatement("CREATE USER unauthorized_user PASSWORD test")) {
        statement.execute();
      }
    } catch (Exception e) {
      // user already exists continue
    }
  }

  @PostMapping("/SqlInjection/attack5")
  @ResponseBody
  public AttackResult completed(
      @RequestParam(required = false) String privilege,
      @RequestParam(required = false) String table,
      @RequestParam(required = false) String grantee) {
    createUser();
    if (privilege == null || table == null || grantee == null) {
      return failed(this).feedback("sql-injection.console.freeform").build();
    }
    String right = privilege.trim().toLowerCase(Locale.ROOT);
    String object = table.trim().toLowerCase(Locale.ROOT);
    String user = grantee.trim().toLowerCase(Locale.ROOT);
    if (!PRIVILEGES.contains(right) || !TABLES.contains(object) || !GRANTEES.contains(user)) {
      return failed(this).feedback("sql-injection.console.identifier").build();
    }
    return grant("GRANT " + right + " ON " + object + " TO " + user);
  }

  private AttackResult grant(String sql) {
    try (Connection connection = dataSource.getConnection();
        Statement statement = connection.createStatement()) {
      statement.execute(sql);
      if (checkSolution(connection)) {
        return success(this).build();
      }
      return failed(this).output("Your statement was: " + sql).build();
    } catch (SQLException e) {
      return failed(this).feedback("sql-injection.console.failed").build();
    }
  }

  private boolean checkSolution(Connection connection) {
    try {
      var stmt =
          connection.prepareStatement(
              "SELECT * FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE TABLE_NAME = ? AND GRANTEE ="
                  + " ?");
      stmt.setString(1, "GRANT_RIGHTS");
      stmt.setString(2, "UNAUTHORIZED_USER");
      var resultSet = stmt.executeQuery();
      return resultSet.next();
    } catch (SQLException throwables) {
      return false;
    }
  }
}
