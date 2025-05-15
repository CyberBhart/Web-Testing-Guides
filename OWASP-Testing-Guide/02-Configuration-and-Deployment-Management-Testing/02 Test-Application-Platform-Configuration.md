# **Testing Application Platform Configuration**

## **Overview**

Testing Application Platform Configuration (WSTG-CONF-02) involves assessing the configuration of the web application’s platform (e.g., web servers, application servers, frameworks) to ensure it is securely configured, minimizing vulnerabilities that could expose the application to attacks. According to OWASP, misconfigured application platforms can lead to unauthorized access, information disclosure, or exploitation of default settings. This test focuses on verifying secure configurations of server software, frameworks, and related components to mitigate misconfiguration risks.

**Impact**: Misconfigured application platforms can lead to:
- Unauthorized access to sensitive files or directories.
- Information disclosure via verbose error messages or server banners.
- Exploitation of default or weak configurations.
- Security bypass due to improper access controls.

This guide provides a practical, hands-on methodology for testing application platform configuration, adhering to OWASP’s WSTG-CONF-02, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing application platform configuration, with at least two specific commands or configurations per tool for real security testing:

- **Nikto**: Scans web servers for misconfigurations and vulnerabilities.
- **Burp Suite Community Edition**: Analyzes HTTP responses for headers and misconfigurations.
- **Nmap**: Detects server software versions and configurations.
- **Wfuzz**: Brute-forces directories and files to find exposed resources.
- **Curl**: Tests HTTP methods and error responses.
- **Gobuster**: Enumerates directories and file extensions.

### **Tool Setup Instructions**

1. **Nikto**:
   - Install on Linux: `sudo apt install nikto`.
   - Verify: `nikto -Version`.
2. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Verify: `curl -x http://127.0.0.1:8080 http://example.com`.
3. **Nmap**:
   - Install on Linux: `sudo apt install nmap`.
   - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/download.html).
   - Verify: `nmap --version`.
4. **Wfuzz**:
   - Install: `pip install wfuzz`.
   - Verify: `wfuzz --version`.
5. **Curl**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
6. **Gobuster**:
   - Install: `sudo apt install gobuster`.
   - Download: [github.com/OJ/gobuster](https://github.com/OJ/gobuster).
   - Verify: `gobuster --version`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-CONF-02, focusing on testing server software versions, default configurations, directory/file access, error handling, security headers, HTTP methods, and framework settings.

### **1. Scan for Server Software Versions with Nmap**

Identify outdated or vulnerable server software versions.

**Steps**:
1. **Configure Nmap**:
   - Ensure permission to scan the target (`example.com`).
2. **Run Version Scan**:
   - Detect web server (e.g., Apache, Nginx) and application server versions.
3. **Analyze Findings**:
   - Vulnerable: Outdated versions (e.g., Apache 2.4.18).
   - Expected secure response: Latest, patched versions.
4. **Document Findings**:
   - Save Nmap output.

**Nmap Commands**:
- **Command 1**: Version detection:
  ```bash
  nmap -sV -p 80,443 example.com -oN nmap_version.txt
  ```
- **Command 2**: Script scan for vulnerabilities:
  ```bash
  nmap --script http-enum,http-server-header -p 80,443 example.com -oN nmap_scripts.txt
  ```

**Example Vulnerable Output**:
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 (vulnerable to CVE-2017-7679)
```

**Remediation**:
- Update server software:
  ```bash
  sudo apt update
  sudo apt upgrade apache2
  ```

### **2. Check for Misconfigurations with Nikto**

Identify default configurations, exposed files, or server misconfigurations.

**Steps**:
1. **Configure Nikto**:
   - Ensure permission to scan the target.
2. **Run Nikto Scan**:
   - Scan for default files, directories, or misconfigurations.
3. **Analyze Findings**:
   - Vulnerable: Exposed `/admin` or default files (e.g., `/server-status`).
   - Expected secure response: No sensitive resources exposed.
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
+ Server: Apache/2.4.18 (vulnerable)
+ /manager/html: Tomcat Manager exposed
```

**Remediation**:
- Secure Tomcat Manager:
  ```xml
  <!-- /conf/tomcat-users.xml -->
  <tomcat-users>
      <!-- Remove default users -->
  </tomcat-users>
  ```
  ```apache
  <Location /manager>
      Require ip 192.168.1.0/24
  </Location>
  ```

### **3. Test Directory and File Access with Gobuster**

Verify that sensitive directories and files are protected.

**Steps**:
1. **Configure Gobuster**:
   - Use a wordlist (e.g., `/usr/share/wordlists/dirb/common.txt`).
2. **Run Directory Brute-Force**:
   - Enumerate directories and files (e.g., `/admin`, `.bak`).
3. **Analyze Findings**:
   - Vulnerable: Accessible sensitive directories or files.
   - Expected secure response: HTTP 403 or 404 for sensitive paths.
4. **Document Findings**:
   - Save Gobuster output.

**Gobuster Commands**:
- **Command 1**: Directory enumeration:
  ```bash
  gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -o gobuster_dirs.txt
  ```
- **Command 2**: File extension enumeration:
  ```bash
  gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x .bak,.conf,.xml -o gobuster_files.txt
  ```

**Example Vulnerable Output**:
```
/admin (Status: 200)
/config.bak (Status: 200)
```

**Remediation**:
- Restrict access:
  ```nginx
  location /admin {
      deny all;
  }
  location ~* \.(bak|conf|xml)$ {
      deny all;
  }
  ```

### **4. Test Error Handling with Curl**

Check for verbose error messages exposing sensitive information.

**Steps**:
1. **Trigger Errors**:
   - Send invalid requests to trigger error responses.
2. **Analyze Responses**:
   - Look for stack traces, database details, or internal paths.
3. **Analyze Findings**:
   - Vulnerable: Error messages reveal sensitive data.
   - Expected secure response: Generic error pages.
4. **Document Findings**:
   - Save Curl responses.

**Curl Commands**:
- **Command 1**: Trigger error with invalid path:
  ```bash
  curl -i http://example.com/nonexistent
  ```
- **Command 2**: Test invalid parameter:
  ```bash
  curl -i "http://example.com/page?id=invalid"
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Error: SQLSTATE[42000]: Syntax error at /var/www/html/page.php:32
```

**Remediation**:
- Disable verbose errors (PHP):
  ```php
  ; php.ini
  display_errors = Off
  log_errors = On
  ```

### **5. Test Security Headers with Burp Suite**

Ensure security headers are properly configured.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope.
2. **Capture Responses**:
   - Check headers like CSP, X-Frame-Options, HSTS.
3. **Analyze Findings**:
   - Vulnerable: Missing or weak headers.
   - Expected secure response: All headers present (e.g., `X-Frame-Options: DENY`).
4. **Document Findings**:
   - Save response headers.

**Burp Suite Commands**:
- **Command 1**: Check headers:
  ```
  HTTP History -> Select GET / -> Response tab -> Look for X-Frame-Options, Content-Security-Policy
  ```
- **Command 2**: Test header absence:
  ```
  HTTP History -> Select GET / -> Send to Repeater -> Remove X-Frame-Options -> Click Send -> Check response
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
[No Content-Security-Policy]
```

**Remediation**:
- Add security headers (Nginx):
  ```nginx
  add_header X-Frame-Options "DENY" always;
  add_header Content-Security-Policy "default-src 'self'" always;
  ```

### **6. Test HTTP Methods with Curl**

Verify that unsafe HTTP methods are disabled.

**Steps**:
1. **Test HTTP Methods**:
   - Send requests with methods like TRACE, PUT, DELETE.
2. **Analyze Responses**:
   - Check if methods are enabled.
3. **Analyze Findings**:
   - Vulnerable: TRACE or PUT enabled.
   - Expected secure response: HTTP 405 or 403.
4. **Document Findings**:
   - Save Curl responses.

**Curl Commands**:
- **Command 1**: Test TRACE method:
  ```bash
  curl -i -X TRACE http://example.com
  ```
- **Command 2**: Test PUT method:
  ```bash
  curl -i -X PUT http://example.com/test.txt -d "test"
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
TRACE / HTTP/1.1
```

**Remediation**:
- Disable unsafe methods (Apache):
  ```apache
  <Limit TRACE PUT DELETE>
      Order deny,allow
      Deny from all
  </Limit>
  ```

### **7. Automate Testing with Python Script**

Automate testing for misconfigurations and security headers.

**Steps**:
1. **Write Python Script**:
   - Create a script to check headers, methods, and file access:
     ```python
     import requests

     target = 'http://example.com'

     # Check security headers
     response = requests.get(target)
     headers = response.headers
     required_headers = {
         'X-Frame-Options': 'DENY',
         'Content-Security-Policy': "default-src 'self'",
         'X-Content-Type-Options': 'nosniff'
     }
     print("Security Headers:")
     for header, expected in required_headers.items():
         value = headers.get(header, 'Missing')
         print(f"{header}: {value}")
         if value == 'Missing':
             print(f"Vulnerable: Missing {header}")

     # Test HTTP methods
     methods = ['TRACE', 'PUT']
     print("\nHTTP Methods:")
     for method in methods:
         response = requests.request(method, target)
         print(f"{method}: Status={response.status_code}")
         if response.status_code == 200:
             print(f"Vulnerable: {method} enabled")

     # Test sensitive files
     files = ['/admin', '/config.bak']
     print("\nSensitive Files:")
     for file in files:
         response = requests.get(f"{target}{file}")
         print(f"{file}: Status={response.status_code}")
         if response.status_code == 200:
             print(f"Vulnerable: {file} accessible")
     ```
2. **Run Script**:
   - Install dependencies: `pip install requests`.
   - Execute: `python3 test_platform_config.py`.
3. **Analyze Findings**:
   - Vulnerable: Missing headers, enabled methods, or accessible files.
   - Expected secure response: All headers present; methods disabled; files inaccessible.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run platform config test:
  ```bash
  python3 test_platform_config.py
  ```
- **Command 2**: Test security headers:
  ```bash
  python3 -c "import requests; r=requests.get('http://example.com'); h=r.headers; print('X-Frame-Options:', h.get('X-Frame-Options', 'Missing'))"
  ```

**Example Vulnerable Output**:
```
Security Headers:
X-Frame-Options: Missing
Vulnerable: Missing X-Frame-Options

HTTP Methods:
TRACE: Status=200
Vulnerable: TRACE enabled

Sensitive Files:
/admin: Status=200
Vulnerable: /admin accessible
```

**Remediation**:
- Secure configuration (Nginx):
  ```nginx
  server {
      add_header X-Frame-Options "DENY" always;
      location /admin {
          deny all;
      }
      if ($request_method !~ ^(GET|POST)$) {
          return 405;
      }
  }
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-CONF-02 with practical scenarios based on common application platform vulnerabilities observed in penetration testing.

### **Test 1: Outdated Server Version**

**Objective**: Identify vulnerable server software.

**Steps**:
1. **Run Version Scan**:
   - Use Nmap:
     ```bash
     nmap -sV -p 80,443 example.com
     ```
2. **Analyze Results**:
   - Check for outdated versions.
   - Expected secure response: Latest versions.
3. **Save Results**:
   - Save Nmap output.

**Example Vulnerable Output**:
```
80/tcp open  http    Apache httpd 2.4.18
```

**Remediation**:
```bash
sudo apt upgrade apache2
```

### **Test 2: Exposed Sensitive Directory**

**Objective**: Ensure sensitive directories are protected.

**Steps**:
1. **Run Directory Scan**:
   - Use Gobuster:
     ```bash
     gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt
     ```
2. **Analyze Results**:
   - Check for `/admin` or `/config`.
   - Expected secure response: HTTP 403/404.
3. **Save Results**:
   - Save Gobuster output.

**Example Vulnerable Output**:
```
/admin (Status: 200)
```

**Remediation**:
```apache
<Directory /admin>
    Require all denied
</Directory>
```

### **Test 3: Verbose Error Messages**

**Objective**: Verify error messages are generic.

**Steps**:
1. **Trigger Error**:
   - Use Curl:
     ```bash
     curl -i http://example.com/nonexistent
     ```
2. **Analyze Response**:
   - Check for stack traces.
   - Expected secure response: Generic error.
3. **Save Results**:
   - Save Curl output.

**Example Vulnerable Response**:
```
Error: Exception at /var/www/html/index.php:45
```

**Remediation**:
```php
; php.ini
display_errors = Off
```

### **Test 4: Missing Security Headers**

**Objective**: Ensure security headers are present.

**Steps**:
1. **Check Headers**:
   - Use Burp Suite:
     ```
     HTTP History -> Select GET / -> Response tab -> Check headers
     ```
2. **Analyze Results**:
   - Look for CSP, X-Frame-Options.
   - Expected secure response: All headers present.
3. **Save Results**:
   - Save Burp Suite output.

**Example Vulnerable Response**:
```
[No X-Frame-Options]
```

**Remediation**:
```nginx
add_header X-Frame-Options "DENY" always;
```

## **Additional Tips**

- **Test All Components**: Check web servers, application servers, and frameworks.
- **Combine Tools**: Use Nikto for scanning, Gobuster for enumeration, and Burp Suite for header analysis.
- **Gray-Box Testing**: If configurations are accessible, review server config files (e.g., `httpd.conf`, `php.ini`).
- **Document Thoroughly**: Save all commands, outputs, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for scanning, as aggressive scans may trigger security alerts or disrupt services.
- **References**: [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/), [CIS Web Server Benchmarks](https://www.cisecurity.org/cis-benchmarks/).