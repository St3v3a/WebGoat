/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Email;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * @author nbaars
 * @since 4/8/17.
 */
@RestController
@Slf4j
public class Assignment7 implements AssignmentEndpoint {

  private static final int MAX_PENDING_RESETS = 1024;
  private static final String TEMPLATE =
      "Hi, you requested a password reset link, please use this <a target='_blank'"
          + " href='%s/challenge/7/reset-password/%s'>link</a> to reset your"
          + " password.\n"
          + " \n\n"
          + "If you did not request this password change you can ignore this message.\n"
          + "If you have any comments or questions, please do not hesitate to reach us at"
          + " support@webgoat-cloud.org\n\n"
          + "Kind regards, \n"
          + "Team WebGoat";

  private record ResetRequest(String username, Instant expiresAt) {}

  private final Map<String, ResetRequest> resetRequests = new ConcurrentHashMap<>();
  private final RestTemplate restTemplate;
  private final String webWolfMailURL;
  private final String resetBaseUrl;

  public Assignment7(
      RestTemplate restTemplate,
      @Value("${webwolf.mail.url}") String webWolfMailURL,
      @Value("${webgoat.challenge.reset-base-url:${webgoat.url}}") String resetBaseUrl) {
    this.restTemplate = restTemplate;
    this.webWolfMailURL = webWolfMailURL;
    this.resetBaseUrl = resetBaseUrl;
  }

  @GetMapping("/challenge/7/reset-password/{link}")
  public ResponseEntity<String> resetPassword(
      @PathVariable(value = "link") String link, HttpServletRequest servletRequest) {
    if (!"GET".equals(servletRequest.getMethod())) {
      return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).build();
    }
    ResetRequest request = resetRequests.remove(link);
    if (request != null && Instant.now().isBefore(request.expiresAt())) {
      return ResponseEntity.accepted()
          .body("<h1>Reset link accepted for " + HtmlUtils.htmlEscape(request.username()) + "</h1>");
    }
    return ResponseEntity.status(HttpStatus.I_AM_A_TEAPOT)
        .body("That is not the reset link for admin");
  }

  @PostMapping("/challenge/7")
  @ResponseBody
  public AttackResult sendPasswordResetLink(@RequestParam String email) {
    if (!StringUtils.hasText(email) || email.indexOf('@') < 1) {
      return failed(this).feedback("email.send").feedbackArgs(email).build();
    }
    String username = email.substring(0, email.indexOf('@'));
    String token = new PasswordResetLink().createPasswordReset(username, "webgoat");
    Instant now = Instant.now();
    synchronized (resetRequests) {
      resetRequests.entrySet().removeIf(e -> !now.isBefore(e.getValue().expiresAt()));
      if (resetRequests.size() >= MAX_PENDING_RESETS) {
        resetRequests.entrySet().stream()
            .min(Comparator.comparing(e -> e.getValue().expiresAt()))
            .ifPresent(e -> resetRequests.remove(e.getKey(), e.getValue()));
      }
      resetRequests.put(token, new ResetRequest(username, now.plusSeconds(600)));
    }
    Email mail =
        Email.builder()
            .title("Your password reset link for challenge 7")
            .contents(String.format(TEMPLATE, resetBaseUrl, token))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .time(LocalDateTime.now())
            .build();
    restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
    return failed(this).feedback("email.send").feedbackArgs(email).build();
  }

  @GetMapping(value = "/challenge/7/.git", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
  @ResponseBody
  public ClassPathResource git() {
    return new ClassPathResource("lessons/challenges/challenge7/git.zip");
  }
}
