/*
 * SPDX-FileCopyrightText: Copyright © 2022 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.integration;

import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.RestAssured;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

public class ChallengeIntegrationTest extends IntegrationTest {

  @Test
  void challenge1LogoDoesNotRevealAdminPassword() {
    startLesson("Challenge1");
    byte[] logo =
        RestAssured.given()
            .cookie("JSESSIONID", getWebGoatCookie())
            .get(webGoatUrlConfig.url("challenge/logo"))
            .then()
            .statusCode(200)
            .extract()
            .asByteArray();
    assertTrue(logo.length > 81220);
    String allegedPin = new String(logo, 81216, 4, StandardCharsets.US_ASCII);
    checkAssignment(
        webGoatUrlConfig.url("challenge/1"),
        Map.of("username", "admin", "password", "!!webgoat_admin_" + allegedPin + "!!"),
        false);
  }

  @Test
  void challenge5BindsThePassword() {
    startLesson("Challenge5");
    checkAssignment(
        webGoatUrlConfig.url("challenge/5"),
        Map.of("username_login", "Larry", "password_login", "' OR '1'='1"),
        false);
    checkAssignment(
        webGoatUrlConfig.url("challenge/5"),
        Map.of("username_login", "Larry", "password_login", "larryknows"),
        true);
  }

  @Test
  void challenge7UsesOneTimeResetLinks() {
    startLesson("Challenge7");
    cleanMailbox();
    RestAssured.given()
        .cookie("JSESSIONID", getWebGoatCookie())
        .get(webGoatUrlConfig.url("challenge/7/.git"))
        .then()
        .statusCode(200);

    checkAssignment(
        webGoatUrlConfig.url("challenge/7"),
        Map.of("email", getUser() + "@webgoat.org"),
        false);
    String mailbox =
        RestAssured.given()
            .cookie("WEBWOLFSESSION", getWebWolfCookie())
            .get(webWolfUrlConfig.url("mail"))
            .then()
            .extract()
            .asString();
    Matcher link = Pattern.compile("/challenge/7/reset-password/([a-f0-9]{64})").matcher(mailbox);
    assertTrue(link.find());
    String resetPath = "challenge/7/reset-password/" + link.group(1);
    String accepted =
        RestAssured.given()
            .cookie("JSESSIONID", getWebGoatCookie())
            .get(webGoatUrlConfig.url(resetPath))
            .then()
            .statusCode(HttpStatus.ACCEPTED.value())
            .extract()
            .asString();
    Assertions.assertThat(accepted).doesNotContain("flag:");
    RestAssured.given()
        .cookie("JSESSIONID", getWebGoatCookie())
        .get(webGoatUrlConfig.url(resetPath))
        .then()
        .statusCode(HttpStatus.I_AM_A_TEAPOT.value());
  }
}
