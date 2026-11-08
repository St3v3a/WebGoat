/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class DOMCrossSiteScriptingTest extends LessonTest {

  @Test
  void success() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/CrossSiteScripting/phone-home-xss")
                .header("webgoat-requested-by", "dom-xss-vuln")
                .param("param1", "42")
                .param("param2", "24"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void failure() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/CrossSiteScripting/phone-home-xss")
                .header("webgoat-requested-by", "wrong-value")
                .param("param1", "22")
                .param("param2", "20"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void chromeDevToolsNumberDoesNotCompleteXssAssignments() throws Exception {
    MockHttpSession session = new MockHttpSession();
    MvcResult issued =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/ChromeDevTools/phone-home")
                    .session(session)
                    .param("param1", "42")
                    .param("param2", "24"))
            .andExpect(status().isOk())
            .andReturn();
    String output =
        new ObjectMapper()
            .readTree(issued.getResponse().getContentAsString())
            .path("output")
            .asText();
    assertTrue(output.startsWith("phoneHome Response is "));
    String number = output.substring("phoneHome Response is ".length());

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/ChromeDevTools/dummy")
                .session(session)
                .param("successMessage", number))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/CrossSiteScripting/dom-follow-up")
                .session(session)
                .param("successMessage", number))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/CrossSiteScriptingStored/stored-xss-follow-up")
                .session(session)
                .param("successMessage", number))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
