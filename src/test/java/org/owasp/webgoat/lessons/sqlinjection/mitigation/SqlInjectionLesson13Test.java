/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson13Test extends LessonTest {

  @ParameterizedTest
  @ValueSource(strings = {"id", "hostname", "ip", "mac", "status", "description"})
  public void ordinarySortColumnsReturnOnlyVisibleServers(String column) throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", column))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$", hasSize(4)))
        .andExpect(jsonPath("$[*].hostname", not(hasItem("webgoat-prd"))))
        .andExpect(jsonPath("$[0].id").exists())
        .andExpect(jsonPath("$[0].ip").exists())
        .andExpect(jsonPath("$[0].mac").exists())
        .andExpect(jsonPath("$[0].status").exists())
        .andExpect(jsonPath("$[0].description").exists());
  }

  @Test
  public void sortingStillUsesTheSelectedColumn() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", "id"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-dev")));
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "hostname"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-acc")));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "CASE WHEN (SELECT ip FROM servers WHERE hostname='webgoat-prd') LIKE '104.%' THEN hostname ELSE id END",
        "id; SELECT * FROM servers",
        "hostname DESC",
        "description --",
        "unknown"
      })
  public void expressionsAndUnknownColumnsAreRejected(String column) throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", column))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void missingColumnIsRejected() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers"))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void mitigationExerciseRequiresRejectedExpressionThenSuccessfulNamedSort()
      throws Exception {
    MockHttpSession session = new MockHttpSession();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionMitigations/attack12a")
                .session(session)
                .param("ip", "104.130.219.202"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .session(session)
                .param("column", "hostname DESC"))
        .andExpect(status().isBadRequest());
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionMitigations/attack12a")
                .session(session)
                .param("safeColumn", "id"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .session(session)
                .param("column", "hostname"))
        .andExpect(status().isOk());
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionMitigations/attack12a")
                .session(session)
                .param("safeColumn", "id"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionMitigations/attack12a")
                .session(session)
                .param("safeColumn", "hostname"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }
}
