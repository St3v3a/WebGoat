/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.mailbox;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.owasp.webgoat.webwolf.WebSecurityConfig;
import org.owasp.webgoat.webwolf.user.UserService;
import org.jsoup.Jsoup;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@WebMvcTest(MailboxController.class)
@Import(WebSecurityConfig.class)
public class MailboxControllerTest {

  @Autowired private MockMvc mvc;
  @MockBean private MailboxRepository mailbox;

  @MockBean private ClientRegistrationRepository clientRegistrationRepository;
  @MockBean private UserService userService;
  @Autowired private ObjectMapper objectMapper;

  @JsonIgnoreProperties("time")
  public static class EmailMixIn {}

  @BeforeEach
  public void setup() {
    objectMapper.addMixIn(Email.class, EmailMixIn.class);
  }

  @Test
  public void sendingMailShouldStoreIt() throws Exception {
    Email email =
        Email.builder()
            .contents("This is a test mail")
            .recipient("test1234@webgoat.org")
            .sender("hacker@webgoat.org")
            .title("Click this mail")
            .time(LocalDateTime.now())
            .build();
    this.mvc
        .perform(
            post("/mail")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(email)))
        .andExpect(status().isCreated());
  }

  @Test
  @WithMockUser(username = "test1234")
  public void userShouldBeAbleToReadOwnEmail() throws Exception {
    Email email =
        Email.builder()
            .contents("This is a test mail")
            .recipient("test1234@webgoat.org")
            .sender("hacker@webgoat.org")
            .title("Click this mail")
            .time(LocalDateTime.now())
            .build();
    Mockito.when(mailbox.findByRecipientOrderByTimeDesc("test1234"))
        .thenReturn(Lists.newArrayList(email));

    this.mvc
        .perform(get("/mail"))
        .andExpect(status().isOk())
        .andExpect(view().name("mailbox"))
        .andExpect(content().string(containsString("Click this mail")))
        .andExpect(content().string(containsString("This is a test mail")))
        .andExpect(
            content()
                .string(
                    containsString(
                        DateTimeFormatter.ofPattern("h:mm a").format(email.getTimestamp()))));
  }

  @Test
  @WithMockUser(username = "test1233")
  public void differentUserShouldNotBeAbleToReadOwnEmail() throws Exception {
    Email email =
        Email.builder()
            .contents("This is a test mail")
            .recipient("test1234@webgoat.org")
            .sender("hacker@webgoat.org")
            .title("Click this mail")
            .time(LocalDateTime.now())
            .build();
    Mockito.when(mailbox.findByRecipientOrderByTimeDesc("test1234"))
        .thenReturn(Lists.newArrayList(email));

    this.mvc
        .perform(get("/mail"))
        .andExpect(status().isOk())
        .andExpect(view().name("mailbox"))
        .andExpect(content().string(not(containsString("Click this mail"))));
  }

  @Test
  @WithMockUser(username = "test1234")
  public void untrustedMailHtmlIsInertButResetLinksRemainClickable() throws Exception {
    Email email =
        Email.builder()
            .contents(
                "<script>alert(1)</script><img src=x onerror=alert(1)>"
                    + "<a href='&#x6a;avascript:alert(1)'>bad link</a>"
                    + "<a href='https://example.test/reset' onclick='alert(1)' target='_blank'>"
                    + "Reset password</a>")
            .recipient("test1234@webgoat.org")
            .sender("hacker@webgoat.org")
            .title("Reset")
            .time(LocalDateTime.now())
            .build();
    Mockito.when(mailbox.findByRecipientOrderByTimeDesc("test1234"))
        .thenReturn(Lists.newArrayList(email));

    MvcResult result = mvc.perform(get("/mail")).andExpect(status().isOk()).andReturn();
    var mailBody = Jsoup.parse(result.getResponse().getContentAsString()).selectFirst(".card-body pre");
    assertNotNull(mailBody);
    assertEquals(0, mailBody.select("script, img, [onerror], [onclick], a[href^=javascript:]").size());
    assertEquals(1, mailBody.select("a[href=https://example.test/reset]").size());
    assertTrue(mailBody.text().contains("Reset password"));
  }

  @Test
  @WithMockUser(username = "test1234")
  public void missingMailBodyDoesNotBreakMailbox() throws Exception {
    Email email =
        Email.builder()
            .recipient("test1234@webgoat.org")
            .sender("hacker@webgoat.org")
            .title("Empty")
            .time(LocalDateTime.now())
            .build();
    Mockito.when(mailbox.findByRecipientOrderByTimeDesc("test1234"))
        .thenReturn(Lists.newArrayList(email));

    mvc.perform(get("/mail"))
        .andExpect(status().isOk())
        .andExpect(content().string(containsString("Empty")));
  }
}
