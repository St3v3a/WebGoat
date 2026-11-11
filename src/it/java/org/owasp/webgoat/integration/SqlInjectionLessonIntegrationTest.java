/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.integration;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class SqlInjectionLessonIntegrationTest extends IntegrationTest {

  public static final String sql_9_account = " ' ";
  public static final String sql_9_operator = "or";
  public static final String sql_9_injection = "'1'='1";
  public static final String sql_10_login_count = "2";
  public static final String sql_10_userid = "1 or 1=1";

  public static final String sql_11_a = "Smith' or '1' = '1";
  public static final String sql_11_b = "3SL99A'  or '1'='1";

  public static final String sql_12_a = "Smith";
  public static final String sql_12_b =
      "3SL99A' ; update employees set salary= '100000' where last_name='Smith";

  public static final String sql_13 = "%update% '; drop table access_log ; --'";

  @Test
  public void runTests() {
    startLesson("SqlInjection");

    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("column", "department");
    params.put("filterColumn", "last_name");
    params.put("value", "Franco");
      checkAssignment(webGoatUrlConfig.url("SqlInjection/attack2"), params, true);

    params.clear();
    params.put("column", "department");
    params.put("newValue", "Sales");
    params.put("filterColumn", "last_name");
    params.put("value", "Barnett");
      checkAssignment(webGoatUrlConfig.url("SqlInjection/attack3"), params, true);

    params.clear();
    params.put("operation", "add");
    params.put("column", "phone");
    params.put("type", "varchar(20)");
      checkAssignment(webGoatUrlConfig.url("SqlInjection/attack4"), params, true);

    params.clear();
    params.put("privilege", "select");
    params.put("table", "grant_rights");
    params.put("grantee", "unauthorized_user");
      checkAssignment(webGoatUrlConfig.url("SqlInjection/attack5"), params, true);

    params.clear();
    params.put("operator", sql_9_operator);
    params.put("account", sql_9_account);
    params.put("injection", sql_9_injection);
      checkAssignment(webGoatUrlConfig.url("SqlInjection/assignment5a"), params, true);

    params.clear();
    params.put("login_count", sql_10_login_count);
    params.put("userid", sql_10_userid);
      checkAssignment(webGoatUrlConfig.url("SqlInjection/assignment5b"), params, true);

    params.clear();
    params.put("name", sql_11_a);
    params.put("auth_tan", sql_11_b);
      checkAssignment(webGoatUrlConfig.url("SqlInjection/attack8"), params, true);

    params.clear();
    params.put("name", sql_12_a);
    params.put("auth_tan", sql_12_b);
      checkAssignment(webGoatUrlConfig.url("SqlInjection/attack9"), params, true);

    params.clear();
    params.put("action_string", sql_13);
      checkAssignment(webGoatUrlConfig.url("SqlInjection/attack10"), params, true);

    checkResults("SqlInjection");
  }
}
