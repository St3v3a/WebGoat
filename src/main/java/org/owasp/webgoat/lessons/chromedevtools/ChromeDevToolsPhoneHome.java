/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.chromedevtools;

import java.security.SecureRandom;
import java.util.Map;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ChromeDevToolsPhoneHome {

  private static final SecureRandom RANDOM = new SecureRandom();
  private final LessonSession lessonSession;

  public ChromeDevToolsPhoneHome(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  @PostMapping("/ChromeDevTools/phone-home")
  public Map<String, String> issueNumber(
      @RequestParam Integer param1, @RequestParam Integer param2) {
    if (param1 != 42 || param2 != 24) {
      return Map.of("output", "");
    }
    String value = String.valueOf(RANDOM.nextInt());
    lessonSession.setValue("chrome-devtools-rand-value", value);
    return Map.of("output", "phoneHome Response is " + value);
  }
}
