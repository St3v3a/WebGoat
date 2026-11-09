/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/JWT/")
@RestController
@AssignmentHints({
  "jwt-jku-hint1",
  "jwt-jku-hint2",
  "jwt-jku-hint3",
  "jwt-jku-hint4",
  "jwt-jku-hint5"
})
public class JWTHeaderJKUEndpoint implements AssignmentEndpoint {
  private static final String KEY_ID = "webgoat-local-rsa-key";
  private static final KeyPair SIGNING_KEYS = createKeyPair();

  private static KeyPair createKeyPair() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048, new SecureRandom());
      return generator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("RSA token verification is unavailable", e);
    }
  }

  @PostMapping("jku/follow/{user}")
  public @ResponseBody String follow(@PathVariable("user") String user) {
    if ("Jerry".equals(user)) {
      return "Following yourself seems redundant";
    } else {
      return "You are now following Tom";
    }
  }

  @GetMapping("jku/token")
  public @ResponseBody String issueJerryToken() {
    Algorithm algorithm =
        Algorithm.RSA256(
            (RSAPublicKey) SIGNING_KEYS.getPublic(), (RSAPrivateKey) SIGNING_KEYS.getPrivate());
    return JWT.create().withKeyId(KEY_ID).withClaim("username", "Jerry").sign(algorithm);
  }

  @PostMapping("jku/delete")
  public @ResponseBody AttackResult resetVotes(@RequestParam("token") String token) {
    if (StringUtils.isEmpty(token)) {
      return failed(this).feedback("jwt-invalid-token").build();
    }
    try {
      var decoded = JWT.decode(token);
      if (!decoded.getHeaderClaim("jku").isMissing()
          || !KEY_ID.equals(decoded.getKeyId())
          || !"RS256".equals(decoded.getAlgorithm())) {
        return failed(this).feedback("jwt-invalid-token").build();
      }
      Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) SIGNING_KEYS.getPublic(), null);
      var verified = JWT.require(algorithm).build().verify(token);
      String username = verified.getClaim("username").asString();
      if ("Jerry".equals(username)) {
        return failed(this).feedback("jwt-final-jerry-account").build();
      }
      if ("Tom".equals(username)) {
        return success(this).build();
      }
      return failed(this).feedback("jwt-final-not-tom").build();
    } catch (JWTVerificationException e) {
      return failed(this).feedback("jwt-invalid-token").build();
    }
  }
}
