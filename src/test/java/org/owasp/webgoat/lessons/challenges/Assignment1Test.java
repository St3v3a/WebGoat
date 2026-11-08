/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.net.InetAddress;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

@TestPropertySource(properties = "webgoat.challenge.admin-password=!!webgoat_admin_test-secret-value!!")
class Assignment1Test extends LessonTest {

  @Autowired private Flags flags;

  @BeforeEach
  public void setup() {}

  @Test
  void configuredAdminPasswordWorks() throws Exception {
    InetAddress addr = InetAddress.getLocalHost();
    String host = addr.getHostAddress();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/challenge/1")
                .header("X-Forwarded-For", host)
                .param("username", "admin")
                .param("password", "!!webgoat_admin_test-secret-value!!"))
        .andExpect(jsonPath("$.feedback", CoreMatchers.containsString("flag: " + flags.getFlag(1))))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }

  @Test
  void logoBytesDoNotRevealAdminPassword() throws Exception {
    byte[] logo =
        mockMvc
            .perform(MockMvcRequestBuilders.get("/challenge/logo"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsByteArray();
    String allegedPin = new String(logo, 81216, 4, StandardCharsets.US_ASCII);
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/challenge/1")
                .param("username", "admin")
                .param("password", SolutionConstants.PASSWORD.replace("1234", allegedPin)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void wrongPassword() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/challenge/1")
                .param("username", "admin")
                .param("password", "wrong"))
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("assignment.not.solved"))))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
