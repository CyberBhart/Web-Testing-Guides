# **Reviewing Old, Backup, and Unreferenced Files for Sensitive Information**

## **Overview**

Reviewing Old, Backup, and Unreferenced Files for Sensitive Information (WSTG-CONF-04) involves testing a web application to identify files that may expose sensitive data due to improper cleanup or misconfiguration. According to OWASP, old, backup, and unreferenced files can reveal credentials, source code, or internal details, enabling attackers to compromise the application. This test focuses on enumerating and reviewing such files to ensure they are not accessible or do not contain sensitive information.

**Impact**: Exposed old, backup, or unreferenced files can lead to:
- Disclosure of sensitive data, such as database credentials or API keys.
- Exposure of source code, revealing vulnerabilities or intellectual property.
- Application compromise through exploitable configurations or scripts.
- Increased attack surface from forgotten or temporary files.

This guide provides a practical, hands-on methodology for testing old, backup, and unreferenced files, adhering to OWASP’s WSTG-CONF-04, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing old, backup, and unreferenced files, with at least two specific commands or configurations per tool for real security testing:

- **Gobuster**: Enumerates directories and files with backup or old extensions.
- **Wfuzz**: Brute-forces files and directories for exposed resources.
- **Burp Suite Community Edition**: Crawls the application and tests file access.
- **Curl**: Tests direct access to suspected files and server responses.
- **Nikto**: Scans for exposed files and misconfigurations.
- **Dirb**: Enumerates directories and files with common names.

### **Tool Setup Instructions**

1. **Gobuster**:
   - Install on Linux: `sudo apt install gobuster`.
   - Download: [github.com/OJ/gobuster](https://github.com/OJ/gobuster).
   - Verify: `gobuster --version`.
2. **Wfuzz**:
   - Install: `pip install wfuzz`.
   - Verify: `wfuzz --version`.
3. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Verify: `curl -x http://127.0.0.1:8080 http://example.com`.
4. **Curl**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
5. **Nikto**:
   - Install on Linux: `sudo apt install nikto`.
   - Verify: `nikto -Version`.
6. **Dirb**:
   - Install on Linux: `sudo apt install dirb`.
   - Verify: `dirb -V`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-CONF-04, focusing on enumerating backup files, old files, unreferenced files, temporary files, configuration files, predictable file names, and checking for directory indexing.

### **1. Enumerate Backup and Old Files with Gobuster**

Identify accessible backup or old files (e.g., `.bak`, `.old`).

**Steps**:
1. **Configure Gobuster**:
   - Use a wordlist (e.g., `/usr/share/wordlists/dirb/common.txt`).
   - Specify backup/old extensions (e.g., `.bak`, `.old`, `.backup`).
2. **Run File Enumeration**:
   - Brute-force files in the root or directories like `/backup` or `/old`.
3. **Analyze Findings**:
   - Vulnerable: Files like `index.php.bak` return HTTP 200.
   - Expected secure response: HTTP 403 or 404 for sensitive files.
4. **Document Findings**:
   - Save Gobuster output.

**Gobuster Commands**:
- **Command 1**: Enumerate backup files:
  ```bash
  gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x .bak,.old,.backup -o gobuster_backup.txt
  ```
- **Command 2**: Target backup directory:
  ```bash
  gobuster dir -u http://example.com/backup -w /usr/share/wordlists/dirb/common.txt -x .zip,.tar.gz,.sql -o gobuster_backup_dir.txt
  ```

**Example Vulnerable Output**:
```
/index.php.bak (Status: 200)
/backup/db_backup.sql (Status: 200)
```

**Remediation**:
- Deny access to backup extensions (Nginx):
  ```nginx
  location ~* \.(bak|old|backup|zip|tar\.gz|sql)$ {
      deny all;
  }
  ```

### **2. Brute-Force Unreferenced Files with Wfuzz**

Check for unreferenced or temporary files not linked in the application.

**Steps**:
1. **Configure Wfuzz**:
   - Use a wordlist for filenames and extensions.
2. **Run File Brute-Force**:
   - Target common unreferenced files (e.g., `test.php`, `temp.log`).
3. **Analyze Findings**:
   - Vulnerable: Files like `debug.log` accessible.
   - Expected secure response: HTTP 404 or 403.
4. **Document Findings**:
   - Save Wfuzz output.

**Wfuzz Commands**:
- **Command 1**: Brute-force unreferenced files:
  ```bash
  wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt -z list,bak-log-inc --sc 200 http://example.com/FUZZ.FUZZ
  ```
- **Command 2**: Target temporary directory:
  ```bash
  wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt -z list,tmp-log-sql --sc 200 http://example.com/tmp/FUZZ.FUZZ
  ```

**Example Vulnerable Output**:
```
200  debug.log
200  temp.sql
```

**Remediation**:
- Remove unreferenced files:
  ```bash
  rm /var/www/html/tmp/debug.log
  ```

### **3. Crawl for Unreferenced Files with Burp Suite**

Use web crawling to identify unreferenced files.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope.
2. **Run Crawler**:
   - Crawl the application to map files and directories.
   - Manually test unreferenced files found in crawl results (e.g., `test.php`).
3. **Analyze Findings**:
   - Vulnerable: Unreferenced files like `test.php` accessible.
   - Expected secure response: HTTP 403 or 404.
4. **Document Findings**:
   - Save Burp Suite crawl results.

**Burp Suite Commands**:
- **Command 1**: Start crawl:
  ```
  Target -> Site map -> Right-click example.com -> Crawl -> Start Crawl -> Check Crawl Results for .bak, .log
  ```
- **Command 2**: Test unreferenced file:
  ```
  HTTP History -> Select GET / -> Send to Repeater -> Change to GET /test.php -> Click Send
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
<?php echo "Test script"; ?>
```

**Remediation**:
- Restrict access (Apache):
  ```apache
  <Files "test.php">
      Order Deny,Allow
      Deny from all
  </Files>
  ```

### **4. Test Predictable File Names with Curl**

Check for files with predictable names (e.g., date-based backups).

**Steps**:
1. **Test Predictable Files**:
   - Request files like `backup_2025-05-08.sql` or `config.bak`.
2. **Analyze Responses**:
   - Check for HTTP 200 and sensitive content.
3. **Analyze Findings**:
   - Vulnerable: Predictable files accessible.
   - Expected secure response: HTTP 404 or 403.
4. **Document Findings**:
   - Save Curl responses.

**Curl Commands**:
- **Command 1**: Test date-based backup:
  ```bash
  curl -i http://example.com/backup/backup_2025-05-08.sql
  ```
- **Command 2**: Test common backup:
  ```bash
  curl -i http://example.com/config.bak
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/plain
CREATE TABLE users (id INT, username VARCHAR(50));
```

**Remediation**:
- Use unpredictable names and secure storage:
  ```bash
  mv /var/www/html/backup/backup_2025-05-08.sql /var/secure_backups/$(uuidgen).sql
  ```

### **5. Scan for Exposed Files with Nikto**

Identify exposed old or backup files.

**Steps**:
1. **Configure Nikto**:
   - Ensure permission to scan the target.
2. **Run Nikto Scan**:
   - Scan for backup files or misconfigurations.
3. **Analyze Findings**:
   - Vulnerable: Files like `index.php.old` detected.
   - Expected secure response: No sensitive files exposed.
4. **Document Findings**:
   - Save Nikto output.

**Nikto Commands**:
- **Command 1**: Basic scan:
  ```bash
  nikto -h example.com -output nikto_scan.txt
  ```
- **Command 2**: Scan with SSL:
  ```bash
  nikto -h https://example.com -ssl -output nikto_ssl.txt
  ```

**Example Vulnerable Output**:
```
+ /index.php.bak: Backup file found
+ /old/: Directory with old files
```

**Remediation**:
- Remove old files:
  ```bash
  rm /var/www/html/index.php.bak
  ```

### **6. Check Directory Indexing with Dirb**

Ensure directory indexing does not expose backup or old files.

**Steps**:
1. **Configure Dirb**:
   - Use a wordlist (e.g., `/usr/share/dirb/wordlists/common.txt`).
2. **Run Directory Scan**:
   - Test directories like `/backup/` or `/old/` for indexing.
3. **Analyze Findings**:
   - Vulnerable: Directory listing shows files (e.g., `backup.zip`).
   - Expected secure response: HTTP 403 or no listing.
4. **Document Findings**:
   - Save Dirb output.

**Dirb Commands**:
- **Command 1**: Scan for directories:
  ```bash
  dirb http://example.com /usr/share/dirb/wordlists/common.txt -o dirb_dirs.txt
  ```
- **Command 2**: Check specific directory:
  ```bash
  dirb http://example.com/backup /usr/share/dirb/wordlists/common.txt -o dirb_backup.txt
  ```

**Example Vulnerable Output**:
```
+ http://example.com/backup/ (CODE:200|SIZE:1234)
----> Directory indexing enabled: backup.zip, db.sql
```

**Remediation**:
- Disable directory indexing (Nginx):
  ```nginx
  autoindex off;
  ```

### **7. Automate Testing with Python Script**

Automate testing for old, backup, and unreferenced files.

**Steps**:
1. **Write Python Script**:
   - Create a script to test file access and directory indexing:
     ```python
     import requests

     target = 'http://example.com'
     extensions = ['.bak', '.old', '.backup', '.zip', '.sql']
     directories = ['/backup', '/old', '/tmp']
     files = ['config', 'backup', 'index', 'test', 'db']

     # Test backup/old files
     print("Testing backup/old files:")
     for file in files:
         for ext in extensions:
             url = f"{target}/{file}{ext}"
             response = requests.get(url)
             print(f"{url}: Status={response.status_code}")
             if response.status_code == 200:
                 print(f"Vulnerable: {file}{ext} accessible")

     # Test predictable file names
     print("\nTesting predictable file names:")
     for dir in directories:
         for file in files:
             url = f"{target}{dir}/{file}_2025-05-08.sql"
             response = requests.get(url)
             print(f"{url}: Status={response.status_code}")
             if response.status_code == 200:
                 print(f"Vulnerable: Predictable file accessible")

     # Test directory indexing
     print("\nTesting directory indexing:")
     for dir in directories:
         response = requests.get(f"{target}{dir}/")
         print(f"{dir}/: Status={response.status_code}")
         if response.status_code == 200 and '<a href=' in response.text:
             print(f"Vulnerable: Directory indexing enabled at {dir}")
     ```
2. **Run Script**:
   - Install dependencies: `pip install requests`.
   - Execute: `python3 test_backup_files.py`.
3. **Analyze Findings**:
   - Vulnerable: Accessible files or directory indexing detected.
   - Expected secure response: HTTP 403/404 for files; no indexing.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run backup files test:
  ```bash
  python3 test_backup_files.py
  ```
- **Command 2**: Test specific backup file:
  ```bash
  python3 -c "import requests; r=requests.get('http://example.com/index.php.bak'); print(r.status_code, 'Vulnerable' if r.status_code==200 else 'Secure')"
  ```

**Example Vulnerable Output**:
```
Testing backup/old files:
http://example.com/index.php.bak: Status=200
Vulnerable: index.php.bak accessible

Testing predictable file names:
http://example.com/backup/db_2025-05-08.sql: Status=200
Vulnerable: Predictable file accessible

Testing directory indexing:
/backup/: Status=200
Vulnerable: Directory indexing enabled at /backup
```

**Remediation**:
- Secure configuration (Apache):
  ```apache
  <FilesMatch "\.(bak|old|backup|zip|sql)$">
      Order Deny,Allow
      Deny from all
  </FilesMatch>
  Options -Indexes
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-CONF-04 with practical scenarios based on common vulnerabilities involving old, backup, and unreferenced files observed in penetration testing.

### **Test 1: Backup File Exposure**

**Objective**: Identify accessible backup files.

**Steps**:
1. **Run File Scan**:
   - Use Gobuster:
     ```bash
     gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x .bak,.zip
     ```
2. **Analyze Results**:
   - Check for files like `backup.zip`.
   - Expected secure response: HTTP 403/404.
3. **Save Results**:
   - Save Gobuster output.

**Example Vulnerable Output**:
```
/backup.zip (Status: 200)
```

**Remediation**:
```nginx
location ~* \.zip$ {
    deny all;
}
```

### **Test 2: Old File Access**

**Objective**: Ensure old files are not exposed.

**Steps**:
1. **Run Brute-Force**:
   - Use Wfuzz:
     ```bash
     wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt -z list,old-bak --sc 200 http://example.com/FUZZ.FUZZ
     ```
2. **Analyze Results**:
   - Check for `index.php.old`.
   - Expected secure response: HTTP 404.
3. **Save Results**:
   - Save Wfuzz output.

**Example Vulnerable Output**:
```
200  index.php.old
```

**Remediation**:
```bash
rm /var/www/html/index.php.old
```

### **Test 3: Unreferenced File Exposure**

**Objective**: Verify unreferenced files are protected.

**Steps**:
1. **Run Crawl**:
   - Use Burp Suite:
     ```
     Target -> Crawl -> Start Crawl -> Check for test.php, debug.log
     ```
2. **Analyze Response**:
   - Test access to `test.php`.
   - Expected secure response: HTTP 403.
3. **Save Results**:
   - Save Burp Suite output.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Test PHP Script
```

**Remediation**:
```apache
<Files "test.php">
    Deny from all
</Files>
```

### **Test 4: Directory Indexing**

**Objective**: Ensure directory indexing is disabled.

**Steps**:
1. **Test Directory**:
   - Use Dirb:
     ```bash
     dirb http://example.com/backup /usr/share/dirb/wordlists/common.txt
     ```
2. **Analyze Response**:
   - Check for file listings.
   - Expected secure response: HTTP 403.
3. **Save Results**:
   - Save Dirb output.

**Example Vulnerable Output**:
```
+ http://example.com/backup/ (CODE:200)
----> backup.sql, backup.zip
```

**Remediation**:
```nginx
autoindex off;
```

## **Additional Tips**

- **Test Common Patterns**: Include extensions like `.bak`, `.old`, `.backup`, `.zip`, `.sql`, and directories like `/backup`, `/old`, `/tmp`.
- **Combine Tools**: Use Gobuster for enumeration, Burp Suite for crawling, and Nikto for scanning.
- **Gray-Box Testing**: If server access is available, audit file system for unused files.
- **Document Thoroughly**: Save all commands, outputs, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for file enumeration, as aggressive scans may trigger security alerts or disrupt services.
- **References**: [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html), [OWASP Configuration Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Configuration_Cheat_Sheet.html).