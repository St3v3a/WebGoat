/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.hamcrest.Matchers.is;
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

class MissingFunctionACUsersTest extends LessonTest {

  private static final UsernamePasswordAuthenticationToken ADMIN =
      new UsernamePasswordAuthenticationToken(
          "admin", "", List.of(new SimpleGrantedAuthority(WebGoatUser.ROLE_ADMIN)));
  private static final UsernamePasswordAuthenticationToken PLAYER =
      new UsernamePasswordAuthenticationToken(
          "webgoat", "", List.of(new SimpleGrantedAuthority(WebGoatUser.ROLE_USER)));

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void getUsers() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users")
                .principal(ADMIN)
                .header("Content-type", "application/json"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].username", CoreMatchers.is("Tom")))
        .andExpect(
            jsonPath(
                "$[0].userHash", CoreMatchers.is("Mydnhcy00j2b0m6SjmPz6PUxF9WIeO7tzm665GiZWCo=")))
        .andExpect(jsonPath("$[0].admin", CoreMatchers.is(false)));
  }

  @Test
  void addUser() throws Exception {
    var user =
        """
        {"username":"newUser","password":"newUser12","admin": "true"}
        """;
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/users")
                .principal(ADMIN)
                .header("Content-type", "application/json")
                .content(user))
        .andExpect(status().isOk());

    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users")
                .principal(ADMIN)
                .header("Content-type", "application/json"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.size()", is(4)));
  }

  @Test
  void playerCannotReadOrCreateLessonAdministrators() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users")
                .principal(PLAYER)
                .header("Content-type", "application/json"))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/users-admin-fix")
                .principal(PLAYER)
                .header("Content-type", "application/json")
                .content("{\"username\":\"attacker\",\"password\":\"x\",\"admin\":true}"))
        .andExpect(status().isForbidden());
  }
}
