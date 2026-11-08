/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class Assignment8Test extends LessonTest {

  @Test
  void headCannotVoteOrLeakAFlag() throws Exception {
    var before =
        mockMvc.perform(MockMvcRequestBuilders.get("/challenge/8/votes/")).andReturn();
    int originalVotes =
        new ObjectMapper()
            .readTree(before.getResponse().getContentAsString())
            .path("5")
            .asInt();

    mockMvc
        .perform(MockMvcRequestBuilders.get("/challenge/8/vote/5"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.error", CoreMatchers.is(true)));
    mockMvc
        .perform(MockMvcRequestBuilders.head("/challenge/8/vote/5"))
        .andExpect(status().isOk())
        .andExpect(header().doesNotExist("X-FlagController"));

    var after =
        mockMvc.perform(MockMvcRequestBuilders.get("/challenge/8/votes/")).andReturn();
    int currentVotes =
        new ObjectMapper().readTree(after.getResponse().getContentAsString()).path("5").asInt();
    assertEquals(originalVotes, currentVotes);
  }
}
