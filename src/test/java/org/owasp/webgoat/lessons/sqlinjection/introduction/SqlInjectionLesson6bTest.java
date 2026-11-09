/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.sql.SQLException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.lessons.sqlinjection.advanced.SqlInjectionLesson6b;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson6bTest extends LessonTest {

  @Test
  public void publicSeedIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6b")
                .param("userid_6b", "passW0rD"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void passwordRevealedByPriorLessonStillWorks() throws Exception {
    String response =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                    .param("userid_6a", "Smith'; SELECT * from user_system_data; --"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.lessonCompleted", is(true)))
            .andReturn()
            .getResponse()
            .getContentAsString();
    Matcher match = Pattern.compile("dave, ([A-Za-z0-9]{10}),").matcher(response);
    assertTrue(match.find());
    String currentPassword = match.group(1);
    assertNotEquals("passW0rD", currentPassword);

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6b")
                .param("userid_6b", currentPassword))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  @Test
  public void submitWrongPassword() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6b")
                .param("userid_6b", "John"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void databaseFailureCannotAcceptTheFormerFallback() throws Exception {
    LessonDataSource unavailable = mock(LessonDataSource.class);
    when(unavailable.getConnection()).thenThrow(new SQLException("unavailable"));

    assertFalse(new SqlInjectionLesson6b(unavailable).completed("dave").assignmentSolved());
  }
}
