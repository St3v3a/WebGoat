/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.hamcrest.Matchers.is;
import static org.owasp.webgoat.lessons.jwt.JWTRefreshEndpoint.PASSWORD;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.test.util.ReflectionTestUtils;

@WithWebGoatUser
public class JWTRefreshEndpointTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  private String expiredSignedToken(String user) {
    String key = (String) ReflectionTestUtils.getField(JWTRefreshEndpoint.class, "JWT_PASSWORD");
    return Jwts.builder()
        .setClaims(new HashMap<>(Map.of("user", user, "admin", "false")))
        .setIssuedAt(new Date(System.currentTimeMillis() - 60 * 60 * 1000))
        .setExpiration(new Date(System.currentTimeMillis() - 1000))
        .signWith(SignatureAlgorithm.HS512, key)
        .compact();
  }

  @Test
  void expiredTomTokenCannotUseJerrysRefreshToken() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();

    // First login to obtain tokens for Jerry
    var loginJson = Map.of("user", "Jerry", "password", PASSWORD);
    MvcResult result =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/JWT/refresh/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(loginJson)))
            .andExpect(status().isOk())
            .andReturn();
    Map<String, String> tokens =
        objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
    String refreshToken = tokens.get("refresh_token");

    // Now create a new refresh token for Tom based on Toms old access token and send the refresh
    // token of Jerry
    String accessTokenTom =
        "eyJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE1MjYxMzE0MTEsImV4cCI6MTUyNjIxNzgxMSwiYWRtaW4iOiJmYWxzZSIsInVzZXIiOiJUb20ifQ.DCoaq9zQkyDH25EcVWKcdbyVfUL4c9D4jRvsqOqvi9iAd4QuqmKcchfbU8FNzeBNF9tLeFXHZLU4yRkq-bjm7Q";
    Map<String, Object> refreshJson = new HashMap<>();
    refreshJson.put("refresh_token", refreshToken);
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/newToken")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + accessTokenTom)
                .content(objectMapper.writeValueAsString(refreshJson)))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void unsignedTokenIsRejected() throws Exception {
    String tokenWithNoneAlgorithm =
        Jwts.builder()
            .setHeaderParam("alg", "none")
            .addClaims(Map.of("admin", "true", "user", "Tom"))
            .compact();

    // Now checkout with the new token from Tom
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/checkout")
                .header("Authorization", "Bearer " + tokenWithNoneAlgorithm))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }

  @Test
  void unsignedTokenCannotRenewWithValidRefreshToken() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();
    MvcResult login =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/JWT/refresh/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(Map.of("user", "Jerry", "password", PASSWORD))))
            .andExpect(status().isOk())
            .andReturn();
    Map<String, String> tokens =
        objectMapper.readValue(login.getResponse().getContentAsString(), Map.class);
    String unsigned =
        Jwts.builder().setHeaderParam("alg", "none").addClaims(Map.of("user", "Jerry")).compact();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/newToken")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + unsigned)
                .content(objectMapper.writeValueAsString(Map.of("refresh_token", tokens.get("refresh_token")))))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void unsignedExpiredTokenCannotRenewWithValidRefreshToken() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();
    MvcResult login =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/JWT/refresh/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(Map.of("user", "Jerry", "password", PASSWORD))))
            .andExpect(status().isOk())
            .andReturn();
    Map<String, String> tokens =
        objectMapper.readValue(login.getResponse().getContentAsString(), Map.class);
    String header =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString("{\"alg\":\"HS512\"}".getBytes(StandardCharsets.UTF_8));
    String claims =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString("{\"user\":\"Jerry\",\"exp\":1}".getBytes(StandardCharsets.UTF_8));
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/newToken")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + header + "." + claims + ".")
                .content(objectMapper.writeValueAsString(Map.of("refresh_token", tokens.get("refresh_token")))))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void signedExpiredTokenCanRenewItsOwnRefreshToken() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();
    MvcResult login =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/JWT/refresh/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(Map.of("user", "Jerry", "password", PASSWORD))))
            .andExpect(status().isOk())
            .andReturn();
    Map<String, String> tokens =
        objectMapper.readValue(login.getResponse().getContentAsString(), Map.class);
    String expired = expiredSignedToken("Jerry");
    int signatureStart = expired.lastIndexOf('.') + 1;
    byte[] changedSignature = Base64.getUrlDecoder().decode(expired.substring(signatureStart));
    changedSignature[0] ^= 1;
    String tampered =
        expired.substring(0, signatureStart)
            + Base64.getUrlEncoder().withoutPadding().encodeToString(changedSignature);
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/newToken")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + tampered)
                .content(objectMapper.writeValueAsString(Map.of("refresh_token", tokens.get("refresh_token")))))
        .andExpect(status().isUnauthorized());
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/newToken")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + expired)
                .content(objectMapper.writeValueAsString(Map.of("refresh_token", tokens.get("refresh_token")))))
        .andExpect(status().isOk());
  }

  @Test
  void signedExpiredTomTokenCannotUseJerrysRefreshToken() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();
    MvcResult login =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/JWT/refresh/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(Map.of("user", "Jerry", "password", PASSWORD))))
            .andExpect(status().isOk())
            .andReturn();
    Map<String, String> tokens =
        objectMapper.readValue(login.getResponse().getContentAsString(), Map.class);
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/newToken")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + expiredSignedToken("Tom"))
                .content(objectMapper.writeValueAsString(Map.of("refresh_token", tokens.get("refresh_token")))))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void oldTomTokenFromAccessLogIsRejected() throws Exception {
    String accessTokenTom =
        "eyJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE1MjYxMzE0MTEsImV4cCI6MTUyNjIxNzgxMSwiYWRtaW4iOiJmYWxzZSIsInVzZXIiOiJUb20ifQ.DCoaq9zQkyDH25EcVWKcdbyVfUL4c9D4jRvsqOqvi9iAd4QuqmKcchfbU8FNzeBNF9tLeFXHZLU4yRkq-bjm7Q";
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/checkout")
                .header("Authorization", "Bearer " + accessTokenTom))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }

  @Test
  void checkoutWitRandomTokenShouldFail() throws Exception {
    String accessTokenTom =
        "eyJhbGciOiJIUzUxMiJ9.eyJpLXQiOjE1MjYxMzE0MTEsImV4cCI6MTUyNjIxNzgxMSwiYWRtaW4iOiJmYWxzZSIsInVzZXIiOiJUb20ifQ.DCoaq9zQkyDH25EcVWKcdbyVfUL4c9D4jRvsqOqvi9iAd4QuqmKcchfbU8FNzeBNF9tLeFXHZLU4yRkq-bjm7Q";
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/checkout")
                .header("Authorization", "Bearer " + accessTokenTom))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }

  @Test
  void flowForJerryAlwaysWorks() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();

    var loginJson = Map.of("user", "Jerry", "password", PASSWORD);
    MvcResult result =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/JWT/refresh/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(loginJson)))
            .andExpect(status().isOk())
            .andReturn();
    Map<String, String> tokens =
        objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
    String accessToken = tokens.get("access_token");

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/checkout")
                .header("Authorization", "Bearer " + accessToken))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.feedback", is("User is not Tom but Jerry, please try again")));
  }

  @Test
  void loginShouldNotWorkForJerryWithWrongPassword() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();

    var loginJson = Map.of("user", "Jerry", "password", PASSWORD + "wrong");
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginJson)))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void loginShouldNotWorkForTom() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();

    var loginJson = Map.of("user", "Tom", "password", PASSWORD);
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginJson)))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void newTokenShouldWorkForJerry() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();
    Map<String, Object> loginJson = new HashMap<>();
    loginJson.put("user", "Jerry");
    loginJson.put("password", PASSWORD);
    MvcResult result =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/JWT/refresh/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(loginJson)))
            .andExpect(status().isOk())
            .andReturn();
    Map<String, String> tokens =
        objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
    String accessToken = tokens.get("access_token");
    String refreshToken = tokens.get("refresh_token");

    var refreshJson = Map.of("refresh_token", refreshToken);
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/newToken")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + accessToken)
                .content(objectMapper.writeValueAsString(refreshJson)))
        .andExpect(status().isOk());
  }

  @Test
  void unknownRefreshTokenShouldGiveUnauthorized() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();
    Map<String, Object> loginJson = new HashMap<>();
    loginJson.put("user", "Jerry");
    loginJson.put("password", PASSWORD);
    MvcResult result =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/JWT/refresh/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(loginJson)))
            .andExpect(status().isOk())
            .andReturn();
    Map<String, String> tokens =
        objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
    String accessToken = tokens.get("access_token");

    var refreshJson = Map.of("refresh_token", "wrong_refresh_token");
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/newToken")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + accessToken)
                .content(objectMapper.writeValueAsString(refreshJson)))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void noTokenWhileCheckoutShouldReturn401() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/refresh/checkout"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void noTokenWhileRequestingNewTokenShouldReturn401() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/refresh/newToken"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void noTokenWhileLoginShouldReturn401() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/refresh/login"))
        .andExpect(status().isUnauthorized());
  }
}
