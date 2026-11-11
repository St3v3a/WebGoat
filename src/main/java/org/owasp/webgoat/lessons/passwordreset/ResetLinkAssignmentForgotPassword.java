/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Part of the password reset assignment. Used to send the e-mail.
 *
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {

  private final RestTemplate restTemplate;
  private final String webGoatHost;
  private final String webGoatPort;
  private final String webWolfURL;
  private final String webWolfMailURL;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webgoat.host}") String webGoatHost,
      @Value("${webgoat.port}") String webGoatPort,
      @Value("${webwolf.url}") String webWolfURL,
      @Value("${webwolf.mail.url}") String webWolfMailURL) {
    this.restTemplate = restTemplate;
    this.webGoatHost = webGoatHost;
    this.webGoatPort = webGoatPort;
    this.webWolfURL = webWolfURL;
    this.webWolfMailURL = webWolfMailURL;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email, HttpServletRequest request) {
    String host = request.getHeader(HttpHeaders.HOST);
    // Links are built from the configured origin, never from the Host header. A wildcard bind
    // address is not a usable origin, so it is published as localhost.
    String canonicalHost =
        ("0.0.0.0".equals(webGoatHost) ? "localhost" : webGoatHost) + ":" + webGoatPort;
    if (!isServedHost(host, canonicalHost)) {
      // No reset link is issued, stored or mailed for a request that arrives under a Host this
      // deployment does not serve. WebWolf stands in for the server such a request would send
      // Tom to, so his simulated click still lands there and the attempt stays visible in its
      // request log. It carries a decoy that was never registered as a reset link and cannot
      // change a password.
      if (ResetLinkAssignment.TOM_EMAIL.equals(email)) {
        fakeClickingLinkEmail(webWolfURL, UUID.randomUUID().toString());
      }
      return failed(this).output("Unrecognized reset-link host.").build();
    }

    String resetLink = UUID.randomUUID().toString();
    try {
      sendMailToUser(email, canonicalHost, resetLink);
    } catch (Exception e) {
      return failed(this).output("E-mail can't be send. please try again.").build();
    }
    ResetLinkAssignment.resetLinkToEmail.put(resetLink, email);
    ResetLinkAssignment.resetLinks.add(resetLink);

    return success(this).feedback("email.send").feedbackArgs(email).build();
  }

  private boolean isServedHost(String host, String canonicalHost) {
    if (host == null) {
      return false;
    }
    if (canonicalHost.equalsIgnoreCase(host)) {
      return true;
    }
    boolean local =
        "0.0.0.0".equals(webGoatHost)
            || "127.0.0.1".equals(webGoatHost)
            || "localhost".equalsIgnoreCase(webGoatHost);
    return local
        && (("localhost:" + webGoatPort).equalsIgnoreCase(host)
            || ("127.0.0.1:" + webGoatPort).equals(host));
  }

  private void sendMailToUser(String email, String host, String resetLink) {
    int index = email.indexOf("@");
    String username = email.substring(0, index == -1 ? email.length() : index);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            .contents(String.format(ResetLinkAssignment.TEMPLATE, host, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }

  private void fakeClickingLinkEmail(String webWolfURL, String decoy) {
    try {
      HttpHeaders httpHeaders = new HttpHeaders();
      HttpEntity<Void> httpEntity = new HttpEntity<>(httpHeaders);
      new RestTemplate()
          .exchange(
              String.format("%s/PasswordReset/reset/reset-password/%s", webWolfURL, decoy),
              HttpMethod.GET,
              httpEntity,
              Void.class);
    } catch (Exception e) {
      // don't care
    }
  }
}
