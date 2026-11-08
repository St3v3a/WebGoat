/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import lombok.Getter;
import lombok.SneakyThrows;
import org.apache.commons.io.FilenameUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.FileSystemUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

@Getter
public class ProfileUploadBase implements AssignmentEndpoint {

  private final String webGoatHomeDirectory;

  public ProfileUploadBase(String webGoatHomeDirectory) {
    this.webGoatHomeDirectory = webGoatHomeDirectory;
  }

  protected AttackResult execute(MultipartFile file, String fullName, String username) {
    if (file.isEmpty()) {
      return failed(this).feedback("path-traversal-profile-empty-file").build();
    }
    if (StringUtils.isEmpty(fullName)) {
      return failed(this).feedback("path-traversal-profile-empty-name").build();
    }
    if (!isSafeFileName(fullName) || !isSafeFileName(username)) {
      return failed(this).feedback("path-traversal-profile-attempt").build();
    }

    try {
      File uploadDirectory = cleanupAndCreateDirectoryForUser(username);
      Path uploadedFile = uploadDirectory.toPath().resolve(fullName);
      Files.write(
          uploadedFile,
          file.getBytes(),
          StandardOpenOption.CREATE,
          StandardOpenOption.TRUNCATE_EXISTING,
          LinkOption.NOFOLLOW_LINKS);
      return informationMessage(this)
          .feedback("path-traversal-profile-updated")
          .feedbackArgs(uploadedFile.toAbsolutePath())
          .build();

    } catch (IOException e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  protected File cleanupAndCreateDirectoryForUser(String username) throws IOException {
    if (!isSafeFileName(username)) {
      throw new IOException("Invalid profile directory");
    }
    var uploadDirectory = new File(this.webGoatHomeDirectory, "/PathTraversal/" + username);
    if (Files.isSymbolicLink(uploadDirectory.toPath())) {
      throw new IOException("Profile directory is a symbolic link");
    }
    if (uploadDirectory.exists()) {
      FileSystemUtils.deleteRecursively(uploadDirectory);
    }
    Files.createDirectories(uploadDirectory.toPath());
    return uploadDirectory;
  }

  protected boolean isSafeFileName(String name) {
    return name != null
        && !name.isBlank()
        && !name.equals(".")
        && !name.equals("..")
        && name.chars().noneMatch(c -> c < 32 || c == 127 || c == '/' || c == '\\' || c == ':');
  }

  public ResponseEntity<?> getProfilePicture(@CurrentUsername String username) {
    return ResponseEntity.ok()
        .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
        .body(getProfilePictureAsBase64(username));
  }

  protected byte[] getProfilePictureAsBase64(String username) {
    if (!isSafeFileName(username)) {
      return defaultImage();
    }
    var profilePictureDirectory = new File(this.webGoatHomeDirectory, "/PathTraversal/" + username);
    if (Files.isSymbolicLink(profilePictureDirectory.toPath())) {
      return defaultImage();
    }
    var profileDirectoryFiles = profilePictureDirectory.listFiles();

    if (profileDirectoryFiles != null && profileDirectoryFiles.length > 0) {
      return Arrays.stream(profileDirectoryFiles)
          .filter(
              file ->
                  file.isFile()
                      && !Files.isSymbolicLink(file.toPath())
                      && FilenameUtils.isExtension(file.getName(), List.of("jpg", "png")))
          .findFirst()
          .map(
              file -> {
                try {
                  return Base64.getEncoder().encode(Files.readAllBytes(file.toPath()));
                } catch (IOException e) {
                  return defaultImage();
                }
              })
          .orElse(defaultImage());
    } else {
      return defaultImage();
    }
  }

  @SneakyThrows
  protected byte[] defaultImage() {
    var inputStream = getClass().getResourceAsStream("/images/account.png");
    return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
  }
}
