/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.List;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class MissingFunctionYourHashTest extends LessonTest {

  private static final UsernamePasswordAuthenticationToken ADMIN =
      new UsernamePasswordAuthenticationToken(
          "admin", "", List.of(new SimpleGrantedAuthority(WebGoatUser.ROLE_ADMIN)));

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void hashDoesNotMatch() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/access-control/user-hash").param("userHash", "42"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void hashMatches() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/user-hash")
                .principal(ADMIN)
                .param("userHash", "SVtOlaa+ER+w2eoIIVE5/77umvhcsh5V8UyDLUa1Itg="))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }
}
