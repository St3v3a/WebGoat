/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.jsonwebtoken.Jwts;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.test.web.servlet.MvcResult;

public class JWTHeaderKIDEndpointTest extends LessonTest {

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  public void injectedKidCannotSelectSigningKey() throws Exception {
    String key = "deletingTom";
    Map<String, Object> claims = new HashMap<>();
    claims.put("username", "Tom");
    String token =
        Jwts.builder()
            .setHeaderParam(
                "kid", "hacked' UNION select '" + key + "' from INFORMATION_SCHEMA.SYSTEM_USERS --")
            .setIssuedAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toDays(10)))
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, key)
            .compact();
    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", token).content(""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void oldPublicKeyCannotDeleteTom() throws Exception {
    byte[] oldKey = Base64.getDecoder().decode("qwertyqwerty1234");
    String token =
        Jwts.builder()
            .setHeaderParam("kid", "webgoat_key")
            .claim("username", "Tom")
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS256, oldKey)
            .compact();
    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void issuedJerryTokenStillWorks() throws Exception {
    MvcResult issued =
        mockMvc.perform(MockMvcRequestBuilders.get("/JWT/kid/token")).andExpect(status().isOk()).andReturn();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/kid/delete")
                .param("token", issued.getResponse().getContentAsString()))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.feedback", CoreMatchers.is(messages.getMessage("jwt-final-jerry-account"))));
  }

  @Test
  public void shouldNotBeAbleToBypassWithSimpleToken() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/kid/delete")
                .param("token", ".eyJ1c2VybmFtZSI6IlRvbSJ9.")
                .content(""))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }
}
