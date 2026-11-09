/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.mailbox;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@Data
@Builder
@AllArgsConstructor
@Entity
@NoArgsConstructor
public class Email implements Serializable {
  private static final Safelist MAIL_HTML =
      Safelist.none()
          .addTags("a")
          .addAttributes("a", "href")
          .addProtocols("a", "href", "http", "https");

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @JsonIgnore private LocalDateTime time = LocalDateTime.now();

  @Column(length = 1024)
  private String contents;

  private String sender;
  private String title;
  private String recipient;

  public String getSummary() {
    String body = contents == null ? "" : contents;
    return "-" + body.substring(0, Math.min(50, body.length()));
  }

  @JsonIgnore
  public String getSafeContents() {
    return Jsoup.clean(contents == null ? "" : contents, MAIL_HTML);
  }

  public LocalDateTime getTimestamp() {
    return time;
  }

  public String getTime() {
    return DateTimeFormatter.ofPattern("h:mm a").format(time);
  }

  public String getShortSender() {
    return sender.substring(0, sender.indexOf("@"));
  }
}
