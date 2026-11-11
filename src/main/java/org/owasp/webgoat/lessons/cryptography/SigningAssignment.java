/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.HexFormat;
import java.util.Locale;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Signature exercise.
 *
 * <p>The server used to hand out the private half of the very key pair it then trusted, so anyone
 * who could read that response could produce a signature the server accepted. The key the server
 * trusts now never leaves it: the learner gets the public key and a signature the server made,
 * and has to verify rather than forge. A separate practice private key is still available for
 * trying out signing commands, but nothing signed with it is trusted.
 */
@RestController
@AssignmentHints({
  "crypto-signing.hints.1",
  "crypto-signing.hints.2",
  "crypto-signing.hints.3",
  "crypto-signing.hints.4"
})
@Slf4j
public class SigningAssignment implements AssignmentEndpoint {

  private static final String TRUSTED_KEY_PAIR = "signingTrustedKeyPair";
  private static final String PRACTICE_KEY = "signingPracticePrivateKey";

  /** A practice key for trying signing commands. It is unrelated to the key the server trusts. */
  @RequestMapping(path = "/crypto/signing/getprivate", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getPrivateKey(HttpServletRequest request)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    HttpSession session = request.getSession();
    synchronized (session) {
      String practiceKey = (String) session.getAttribute(PRACTICE_KEY);
      if (practiceKey == null) {
        practiceKey = CryptoUtil.getPrivateKeyInPEM(CryptoUtil.generateKeyPair());
        session.setAttribute(PRACTICE_KEY, practiceKey);
      }
      return practiceKey;
    }
  }

  /** The public half of the key the server signs with. */
  @RequestMapping(path = "/crypto/signing/getpublic", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getPublicKey(HttpServletRequest request)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    return CryptoUtil.getPublicKeyInPEM(trustedKeyPair(request.getSession()));
  }

  /** The server's own signature over the hex modulus of its public key. */
  @RequestMapping(path = "/crypto/signing/getsignature", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getSignature(HttpServletRequest request)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    KeyPair trusted = trustedKeyPair(request.getSession());
    return CryptoUtil.signMessage(modulusHex(trusted), trusted.getPrivate());
  }

  @PostMapping("/crypto/signing/verify")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request, @RequestParam String modulus, @RequestParam String signature)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    KeyPair trusted = trustedKeyPair(request.getSession());
    String expectedModulus = modulusHex(trusted);
    String submitted = modulus.trim().toUpperCase(Locale.ROOT);
    if (submitted.length() == expectedModulus.length() + 2 && submitted.startsWith("00")) {
      submitted = submitted.substring(2);
    }
    if (!expectedModulus.equals(submitted)) {
      log.warn("modulus is not the modulus of the trusted key");
      return failed(this).feedback("crypto-signing.modulusnotok").build();
    }
    if (CryptoUtil.verifyMessage(expectedModulus, signature, trusted.getPublic())) {
      return success(this).feedback("crypto-signing.success").build();
    }
    log.warn("signature incorrect");
    return failed(this).feedback("crypto-signing.notok").build();
  }

  private static KeyPair trustedKeyPair(HttpSession session)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    synchronized (session) {
      KeyPair keyPair = (KeyPair) session.getAttribute(TRUSTED_KEY_PAIR);
      if (keyPair == null) {
        keyPair = CryptoUtil.generateKeyPair();
        session.setAttribute(TRUSTED_KEY_PAIR, keyPair);
      }
      return keyPair;
    }
  }

  /** The modulus as OpenSSL prints it: upper-case hex without a sign byte. */
  private static String modulusHex(KeyPair keyPair) {
    byte[] bytes = ((RSAPublicKey) keyPair.getPublic()).getModulus().toByteArray();
    int offset = bytes.length > 1 && bytes[0] == 0 ? 1 : 0;
    return HexFormat.of().withUpperCase().formatHex(bytes, offset, bytes.length);
  }
}
