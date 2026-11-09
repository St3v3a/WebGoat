/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.http.ResponseEntity.ok;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "jwt-refresh-hint1",
  "jwt-refresh-hint2",
  "jwt-refresh-hint3",
  "jwt-refresh-hint4"
})
public class JWTRefreshEndpoint implements AssignmentEndpoint {

  public static final String PASSWORD = "bm5nhSkxCXZkKRy4";
  private static final String JWT_PASSWORD = createSigningKey();
  private static final Map<String, String> validRefreshTokens = new ConcurrentHashMap<>();
  private static final SecureRandom random = new SecureRandom();

  private static String createSigningKey() {
    byte[] key = new byte[64];
    new SecureRandom().nextBytes(key);
    return Base64.getEncoder().encodeToString(key);
  }

  private Jws<Claims> verifiedClaims(String authorization) {
    String token = authorization.startsWith("Bearer ") ? authorization.substring(7) : authorization;
    String[] segments = token.split("\\.", -1);
    if (segments.length != 3 || segments[2].isEmpty()) {
      throw new JwtException("Unsigned token");
    }
    Jws<Claims> jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parseClaimsJws(token);
    if (!"HS512".equals(jwt.getHeader().getAlgorithm())) {
      throw new JwtException("Unexpected signature algorithm");
    }
    return jwt;
  }

  @PostMapping(
      value = "/JWT/refresh/login",
      consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public ResponseEntity follow(@RequestBody(required = false) Map<String, Object> json) {
    if (json == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    if (!(json.get("user") instanceof String) || !(json.get("password") instanceof String)) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    String user = (String) json.get("user");
    String password = (String) json.get("password");

    if ("Jerry".equalsIgnoreCase(user) && PASSWORD.equals(password)) {
      return ok(createNewTokens(user));
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }

  private Map<String, Object> createNewTokens(String user) {
    Map<String, Object> claims = new HashMap<>(Map.of("admin", "false", "user", user));
    String token =
        Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 1000))
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, JWT_PASSWORD)
            .compact();
    Map<String, Object> tokenJson = new HashMap<>();
    byte[] refreshBytes = new byte[32];
    random.nextBytes(refreshBytes);
    String refreshToken = Base64.getUrlEncoder().withoutPadding().encodeToString(refreshBytes);
    validRefreshTokens.put(refreshToken, user);
    tokenJson.put("access_token", token);
    tokenJson.put("refresh_token", refreshToken);
    return tokenJson;
  }

  @PostMapping("/JWT/refresh/checkout")
  @ResponseBody
  public ResponseEntity<AttackResult> checkout(
      @RequestHeader(value = "Authorization", required = false) String token) {
    if (token == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    try {
      Claims claims = verifiedClaims(token).getBody();
      Object user = claims.get("user");
      if ("Tom".equals(user)) {
        return ok(success(this).build());
      }
      return ok(failed(this).feedback("jwt-refresh-not-tom").feedbackArgs(user).build());
    } catch (ExpiredJwtException e) {
      return ok(failed(this).output(e.getMessage()).build());
    } catch (JwtException e) {
      return ok(failed(this).feedback("jwt-invalid-token").build());
    }
  }

  @PostMapping("/JWT/refresh/newToken")
  @ResponseBody
  public ResponseEntity newToken(
      @RequestHeader(value = "Authorization", required = false) String token,
      @RequestBody(required = false) Map<String, Object> json) {
    if (token == null || json == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    Object user;
    try {
      user = verifiedClaims(token).getBody().get("user");
    } catch (ExpiredJwtException e) {
      if (!"HS512".equals(e.getHeader().get("alg"))) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
      }
      user = e.getClaims().get("user");
    } catch (JwtException e) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    Object refreshToken = json.get("refresh_token");
    if (!(user instanceof String) || !(refreshToken instanceof String)) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    } else if (validRefreshTokens.remove(refreshToken, user)) {
      return ok(createNewTokens((String) user));
    } else {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
  }
}
