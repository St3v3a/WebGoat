/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import java.io.StringReader;
import java.util.HashSet;
import java.util.Set;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

final class SafeContactXml {

  private SafeContactXml() {}

  static ContactImpl parse(String xml) throws Exception {
    if (xml == null || xml.length() > 4096) {
      throw new IllegalArgumentException("Invalid contact XML");
    }

    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    var builder = factory.newDocumentBuilder();
    builder.setEntityResolver((publicId, systemId) -> {
      throw new SAXException("External entities are not allowed");
    });
    Element root = builder.parse(new InputSource(new StringReader(xml))).getDocumentElement();
    if (root == null || !"contact".equals(root.getTagName()) || root.hasAttributes()) {
      throw new IllegalArgumentException("Invalid contact root");
    }

    ContactImpl contact = new ContactImpl();
    Set<String> seen = new HashSet<>();
    for (int i = 0; i < root.getChildNodes().getLength(); i++) {
      Node child = root.getChildNodes().item(i);
      if (child.getNodeType() == Node.TEXT_NODE && child.getTextContent().isBlank()) {
        continue;
      }
      if (!(child instanceof Element element) || element.hasAttributes()) {
        throw new IllegalArgumentException("Invalid contact field");
      }
      String name = element.getTagName();
      if (!Set.of("id", "firstName", "lastName", "email").contains(name) || !seen.add(name)) {
        throw new IllegalArgumentException("Unexpected contact field");
      }
      for (int j = 0; j < element.getChildNodes().getLength(); j++) {
        short nodeType = element.getChildNodes().item(j).getNodeType();
        if (nodeType != Node.TEXT_NODE && nodeType != Node.CDATA_SECTION_NODE) {
          throw new IllegalArgumentException("Nested contact field");
        }
      }
      String value = element.getTextContent();
      if (value.length() > 256) {
        throw new IllegalArgumentException("Contact field too long");
      }
      switch (name) {
        case "id" -> {
          if (!value.isBlank()) {
            contact.setId(Integer.valueOf(value.trim()));
          }
        }
        case "firstName" -> contact.setFirstName(value);
        case "lastName" -> contact.setLastName(value);
        case "email" -> contact.setEmail(value);
        default -> throw new IllegalArgumentException("Unexpected contact field");
      }
    }
    return contact;
  }
}
