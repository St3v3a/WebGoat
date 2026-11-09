/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.authbypass;

import java.util.HashMap;
import java.util.Map;

/** Created by appsec on 7/18/17. */
public class AccountVerificationHelper {

  // simulating database storage of verification credentials
  private static final Integer verifyUserId = 1223445;
  private static final Map<String, String> userSecQuestions = new HashMap<>();

  static {
    userSecQuestions.put("secQuestion0", "Dr. Watson");
    userSecQuestions.put("secQuestion1", "Baker Street");
  }

  private static final Map<Integer, Map<String, String>> secQuestionStore = new HashMap<>();

  static {
    secQuestionStore.put(verifyUserId, userSecQuestions);
  }

  // end 'data store set up'

  public boolean verifyAccount(Integer userId, Map<String, String> submittedQuestions) {
    Map<String, String> expected = secQuestionStore.get(userId);
    return expected != null && expected.equals(submittedQuestions);
  }
}
