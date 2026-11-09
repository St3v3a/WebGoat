/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Base64;
import org.junit.jupiter.api.Test;

class EncDecTest {

  @Test
  void issuedCookieRoundTrips() {
    for (String username : new String[] {"webgoat", "admin", "tom"}) {
      assertThat(EncDec.decode(EncDec.encode(username))).isEqualTo(username);
    }
    assertThat(EncDec.decode(EncDec.encode("WEBGOAT"))).isEqualTo("webgoat");
  }

  @Test
  void rejectsLegacyAndTamperedCookies() {
    assertThatThrownBy(() -> EncDec.decode("NjI2MTcwNGI3YTQxNGE1OTU2NzQ2ZDZmNzQ="))
        .isInstanceOf(IllegalArgumentException.class);
    byte[] changed = Base64.getDecoder().decode(EncDec.encode("webgoat"));
    changed[4] ^= 1;
    assertThatThrownBy(() -> EncDec.decode(Base64.getEncoder().encodeToString(changed)))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> EncDec.decode("not-base64!"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void preservesNullContract() {
    assertThat(EncDec.encode(null)).isNull();
    assertThat(EncDec.decode(null)).isNull();
  }
}
