/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.requests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.webwolf.WebSecurityConfig;
import org.owasp.webgoat.webwolf.user.UserService;
import org.jsoup.Jsoup;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.web.exchanges.HttpExchange;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(Requests.class)
@Import(WebSecurityConfig.class)
class RequestsTest {
  @Autowired private MockMvc mvc;
  @MockBean private WebWolfTraceRepository traces;
  @SpyBean private ObjectMapper objectMapper;
  @MockBean private UserService userService;
  @MockBean private ClientRegistrationRepository clientRegistrationRepository;

  @Test
  @WithMockUser(username = "test1234")
  void untrustedPathAndTraceJsonRemainText() throws Exception {
    HttpExchange exchange = mock(HttpExchange.class);
    HttpExchange.Request request = mock(HttpExchange.Request.class);
    when(exchange.getRequest()).thenReturn(request);
    when(exchange.getTimestamp()).thenReturn(Instant.now());
    when(request.getUri())
        .thenReturn(
            URI.create(
                "http://localhost:9090/landing/%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"));
    when(traces.findAll()).thenReturn(List.of(exchange));
    doReturn("{\"header\":\"<svg/onload=alert(1)>\",\"uniqueCode\":\"abc432\"}")
        .when(objectMapper)
        .writeValueAsString(exchange);

    String response = mvc.perform(get("/requests")).andExpect(status().isOk()).andReturn()
        .getResponse().getContentAsString();
    var document = Jsoup.parse(response);
    assertEquals(
        0,
        document
            .select(".card-title img, .card-body img, .card-body svg, [onerror], [onload]")
            .size());
    assertTrue(document.select(".card-title").text().contains("<img src=x onerror=alert(1)>"));
    assertTrue(document.select(".card-body pre").text().contains("<svg/onload=alert(1)>"));
    assertTrue(document.select(".card-body pre").text().contains("abc432"));
  }
}
