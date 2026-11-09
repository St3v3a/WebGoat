/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class VulnerableComponentsLessonTest {

  private static final String CONTACT =
      "<contact><id>1</id><firstName>Bruce</firstName><lastName>Mayhew</lastName>"
          + "<email>webgoat@owasp.org</email></contact>";
  private static final String PROXY =
      "<contact class='dynamic-proxy'><interface>"
          + "org.owasp.webgoat.lessons.vulnerablecomponents.Contact</interface>"
          + "<handler class='java.beans.EventHandler'><target class='java.lang.ProcessBuilder'>"
          + "<command><string>echo</string></command></target><action>start</action></handler>"
          + "</contact>";

  @Test
  void acceptsDocumentedContactShape() throws Exception {
    assertThat(SafeContactXml.parse("<contact/>")).isNotNull();
    ContactImpl parsed = SafeContactXml.parse(CONTACT);
    assertThat(parsed.getId()).isEqualTo(1);
    assertThat(parsed.getFirstName()).isEqualTo("Bruce");
    assertThat(parsed.getEmail()).isEqualTo("webgoat@owasp.org");
    assertThat(SafeContactXml.parse("<contact><firstName><![CDATA[Jane & John]]></firstName></contact>").getFirstName())
        .isEqualTo("Jane & John");
    assertFalse(new VulnerableComponentsLesson().completed(CONTACT).assignmentSolved());
  }

  @Test
  void rejectsTypeMetadataAndNestedGadgets() {
    for (String xml : new String[] {PROXY, "<contact><firstName class='java.lang.ProcessBuilder'>x</firstName></contact>", "<wrapper><contact/></wrapper>"}) {
      assertThrows(Exception.class, () -> SafeContactXml.parse(xml));
      assertFalse(new VulnerableComponentsLesson().completed(xml).assignmentSolved());
    }
  }

  @Test
  void rejectsEntityDeclarationsAndMalformedXml() {
    for (String xml : new String[] {"<!DOCTYPE contact [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><contact><firstName>&x;</firstName></contact>", "bullssjfs", "<contact><unknown>x</unknown></contact>"}) {
      assertThrows(Exception.class, () -> SafeContactXml.parse(xml));
      assertFalse(new VulnerableComponentsLesson().completed(xml).assignmentSolved());
    }
  }
}
