/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import java.util.Map;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class InsecureLoginTask implements AssignmentEndpoint {
  private final InsecureLoginDemoState demoState;

  public InsecureLoginTask(InsecureLoginDemoState demoState) {
    this.demoState = demoState;
  }

  @PostMapping("/InsecureLogin/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if (demoState.consume(username, password)) {
      return success(this).build();
    }
    return failed(this).build();
  }

  @PostMapping(path = "/InsecureLogin/credentials", produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public ResponseEntity<Map<String, String>> credentials() {
    return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(demoState.issue());
  }

  @PostMapping(path = "/InsecureLogin/login", consumes = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public ResponseEntity<Void> login(@RequestBody Map<String, String> credentials) {
    if (demoState.recordLogin(credentials.get("username"), credentials.get("password"))) {
      return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }
}
