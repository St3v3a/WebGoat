/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class SqlInjectionChallengeRegistrationTest extends LessonTest {

  @Test
  void quotedUsernameIsStoredAndCheckedAsOneValue() throws Exception {
    String username = "tom' AND 1=1 --";
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", username)
                .param("email_reg", "example@example.test")
                .param("password_reg", "example-pass"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", containsString("created")));

    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", username)
                .param("email_reg", "example@example.test")
                .param("password_reg", "example-pass"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", containsString("exists")));
  }
}
