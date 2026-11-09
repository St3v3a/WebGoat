/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class InsecureLoginTaskTest extends LessonTest {
  private static final ObjectMapper JSON = new ObjectMapper();

  @Test
  void publicPairAndUnissuedCredentialsDoNotCompleteTheLesson() throws Exception {
    MockHttpSession session = new MockHttpSession();
    task(session, "CaptainJack", "BlackPearl", false);
    task(session, "CaptainJack", "unissued", false);
  }

  @Test
  void interceptedDemoCredentialIsAcceptedOnce() throws Exception {
    MockHttpSession session = new MockHttpSession();
    Map<String, String> issued = issue(session);
    assertNotEquals("BlackPearl", issued.get("password"));
    assertTrue(issued.get("password").length() >= 32);

    task(session, issued.get("username"), issued.get("password"), false);
    login(session, issued, 202);
    task(session, issued.get("username"), issued.get("password"), true);
    task(session, issued.get("username"), issued.get("password"), false);
  }

  @Test
  void reissueAndOtherSessionsCannotReuseTheCredential() throws Exception {
    MockHttpSession firstSession = new MockHttpSession();
    Map<String, String> first = issue(firstSession);
    login(firstSession, first, 202);
    Map<String, String> second = issue(firstSession);

    task(firstSession, first.get("username"), first.get("password"), false);
    task(new MockHttpSession(), second.get("username"), second.get("password"), false);
    login(firstSession, second, 202);
    task(firstSession, second.get("username"), second.get("password"), true);
  }

  @Test
  void invalidDemoLoginCannotAuthorizeTheTask() throws Exception {
    MockHttpSession session = new MockHttpSession();
    Map<String, String> issued = issue(session);
    login(session, Map.of("username", issued.get("username"), "password", "wrong"), 401);
    task(session, issued.get("username"), issued.get("password"), false);
  }

  @Test
  void staticScriptsContainNoReusablePassword() throws Exception {
    ClassLoader loader = getClass().getClassLoader();
    assertNull(loader.getResource("lessons/insecurelogin/js/credentials.js"));
    assertNull(loader.getResource("lessons/ssrf/js/credentials.js"));
    try (InputStream script =
        loader.getResourceAsStream("lessons/insecurelogin/js/insecure-login-demo.js")) {
      assertTrue(script != null);
      String source = new String(script.readAllBytes(), StandardCharsets.UTF_8);
      assertTrue(!source.contains("BlackPearl"));
    }
  }

  private Map<String, String> issue(MockHttpSession session) throws Exception {
    String body =
        mockMvc
            .perform(MockMvcRequestBuilders.post("/InsecureLogin/credentials").session(session))
            .andExpect(status().isOk())
            .andExpect(header().string("Cache-Control", containsString("no-store")))
            .andReturn()
            .getResponse()
            .getContentAsString();
    return JSON.readValue(body, new TypeReference<>() {});
  }

  private void login(MockHttpSession session, Map<String, String> credentials, int expectedStatus)
      throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/InsecureLogin/login")
                .session(session)
                .contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(credentials)))
        .andExpect(status().is(expectedStatus));
  }

  private void task(MockHttpSession session, String username, String password, boolean completed)
      throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/InsecureLogin/task")
                .session(session)
                .param("username", username)
                .param("password", password))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(completed)));
  }
}
