/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_ADMIN;
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

class MissingFunctionACYourHashAdminTest extends LessonTest {

  private static final UsernamePasswordAuthenticationToken ADMIN =
      new UsernamePasswordAuthenticationToken(
          "admin", "", List.of(new SimpleGrantedAuthority(WebGoatUser.ROLE_ADMIN)));
  private static final UsernamePasswordAuthenticationToken PLAYER =
      new UsernamePasswordAuthenticationToken(
          "webgoat", "", List.of(new SimpleGrantedAuthority(WebGoatUser.ROLE_USER)));

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void solve() throws Exception {
    var userHash =
        new DisplayUser(new User("Jerry", "doesnotreallymatter", true), PASSWORD_SALT_ADMIN)
            .getUserHash();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/user-hash-fix")
                .principal(ADMIN)
                .param("userHash", userHash))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.containsString(
                    "Congrats! You really succeeded when you added the user.")))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }

  @Test
  void wrongUserHash() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/user-hash-fix")
                .principal(ADMIN)
                .param("userHash", "wrong"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void correctHashDoesNotAuthorizePlayer() throws Exception {
    var userHash =
        new DisplayUser(new User("Jerry", "doesnotreallymatter", true), PASSWORD_SALT_ADMIN)
            .getUserHash();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/user-hash-fix")
                .principal(PLAYER)
                .param("userHash", userHash))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
