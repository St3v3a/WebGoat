/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_SIMPLE;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class MissingFunctionACYourHashTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void correctHashRequiresApplicationAdmin() throws Exception {
    var hash =
        new DisplayUser(new User("Jerry", "doesnotreallymatter", true), PASSWORD_SALT_SIMPLE)
            .getUserHash();
    var player =
        new UsernamePasswordAuthenticationToken(
            "webgoat", "", List.of(new SimpleGrantedAuthority(WebGoatUser.ROLE_USER)));
    var admin =
        new UsernamePasswordAuthenticationToken(
            "admin", "", List.of(new SimpleGrantedAuthority(WebGoatUser.ROLE_ADMIN)));

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/user-hash")
                .principal(player)
                .param("userHash", hash))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/user-hash")
                .principal(admin)
                .param("userHash", hash))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }
}
