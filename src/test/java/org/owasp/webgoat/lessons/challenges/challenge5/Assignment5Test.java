/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge5;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class Assignment5Test extends LessonTest {

  @Test
  void knownLarryPasswordStillWorks() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/challenge/5")
                .param("username_login", "Larry")
                .param("password_login", "larryknows"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }

  @Test
  void sqlExpressionDoesNotBypassPassword() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/challenge/5")
                .param("username_login", "Larry")
                .param("password_login", "' OR '1'='1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
