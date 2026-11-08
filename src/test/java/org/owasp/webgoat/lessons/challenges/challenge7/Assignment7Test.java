/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Map;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.lessons.challenges.Email;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

class Assignment7Test extends LessonTest {
  private static final String CHALLENGE_PATH = "/challenge/7";
  private static final String RESET_PASSWORD_PATH = CHALLENGE_PATH + "/reset-password";
  private static final String GIT_PATH = CHALLENGE_PATH + "/.git";

  @MockBean private RestTemplate restTemplate;

  @Value("${webwolf.mail.url}")
  String webWolfMailURL;

  @Test
  @DisplayName("Reset password test")
  void resetPasswordTest() throws Exception {
    ResultActions result =
        mockMvc.perform(MockMvcRequestBuilders.get(RESET_PASSWORD_PATH + "/any"));
    result.andExpect(status().is(equalTo(HttpStatus.I_AM_A_TEAPOT.value())));

    result =
        mockMvc.perform(
            MockMvcRequestBuilders.get(
                RESET_PASSWORD_PATH + "/375afe1104f4a487a73823c50a9292a2"));
    result.andExpect(status().is(equalTo(HttpStatus.I_AM_A_TEAPOT.value())));

    mockMvc
        .perform(MockMvcRequestBuilders.post(CHALLENGE_PATH).param("email", "webgoat@webgoat.org"))
        .andExpect(status().isOk());
    ArgumentCaptor<Email> mail = ArgumentCaptor.forClass(Email.class);
    verify(restTemplate).postForEntity(eq(webWolfMailURL), mail.capture(), eq(Object.class));
    Matcher link =
        Pattern.compile("/reset-password/([a-f0-9]{64})").matcher(mail.getValue().getContents());
    assertTrue(link.find());
    String token = link.group(1);

    mockMvc
        .perform(MockMvcRequestBuilders.head(RESET_PASSWORD_PATH + "/" + token))
        .andExpect(status().is(equalTo(HttpStatus.METHOD_NOT_ALLOWED.value())));
    result = mockMvc.perform(MockMvcRequestBuilders.get(RESET_PASSWORD_PATH + "/" + token));
    result.andExpect(status().is(equalTo(HttpStatus.ACCEPTED.value())));
    result.andExpect(content().string(CoreMatchers.not(CoreMatchers.containsString("flag:"))));
    mockMvc
        .perform(MockMvcRequestBuilders.get(RESET_PASSWORD_PATH + "/" + token))
        .andExpect(status().is(equalTo(HttpStatus.I_AM_A_TEAPOT.value())));
  }

  @Test
  @DisplayName("Send password reset link test")
  void sendPasswordResetLinkTest() throws Exception {
    ResultActions result =
        mockMvc.perform(
            MockMvcRequestBuilders.post(CHALLENGE_PATH)
                .param("email", "webgoat@webgoat-cloud.net"));
    result.andExpect(status().isOk());
    result.andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void pendingResetLinksStayBounded() {
    Assignment7 controller =
        new Assignment7(restTemplate, webWolfMailURL, "https://www.webgoat.local/WebGoat");
    for (int i = 0; i < 1025; i++) {
      controller.sendPasswordResetLink("user" + i + "@example.org");
    }
    Map<?, ?> pending = (Map<?, ?>) ReflectionTestUtils.getField(controller, "resetRequests");
    assertEquals(1024, pending.size());
  }

  @Test
  void configuredResetBaseUrlIsUsedInMail() {
    Assignment7 controller =
        new Assignment7(restTemplate, webWolfMailURL, "https://www.webgoat.local/WebGoat");
    controller.sendPasswordResetLink("webgoat@webgoat.org");
    ArgumentCaptor<Email> mail = ArgumentCaptor.forClass(Email.class);
    verify(restTemplate).postForEntity(eq(webWolfMailURL), mail.capture(), eq(Object.class));
    assertTrue(
        mail.getValue()
            .getContents()
            .contains("https://www.webgoat.local/WebGoat/challenge/7/reset-password/"));
  }

  @Test
  @DisplayName("git test")
  void gitTest() throws Exception {
    ResultActions result = mockMvc.perform(MockMvcRequestBuilders.get(GIT_PATH));
    result.andExpect(content().contentType("application/zip"));
  }
}
