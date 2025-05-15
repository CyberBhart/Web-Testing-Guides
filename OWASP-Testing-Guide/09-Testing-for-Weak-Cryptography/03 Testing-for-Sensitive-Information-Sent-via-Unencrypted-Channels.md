# **Testing for Sensitive Information Sent via Unencrypted Channels**

## **Overview**

Testing for Sensitive Information Sent via Unencrypted Channels (WSTG-CRYP-03) involves assessing web applications to identify instances where sensitive data, such as credentials, session tokens, or personal information, is transmitted over unencrypted protocols like HTTP, making it vulnerable to interception through man-in-the-middle (MITM) attacks or network sniffing. According to OWASP, unencrypted channels expose data to attackers, compromising confidentiality and potentially leading to unauthorized access or regulatory violations. This test focuses on inspecting HTTP traffic, form submissions, API calls, cookies, and mixed content to detect unencrypted sensitive data and ensure all communications use secure protocols (e.g., HTTPS with TLS).

**Impact**: Sending sensitive information over unencrypted channels can lead to:
- Exposure of user credentials, session tokens, or personal data (e.g., credit card numbers).
- Unauthorized access to user accounts or sensitive resources via intercepted data.
- Regulatory non-compliance (e.g., GDPR, PCI-DSS) and reputational damage.
- Increased risk of session hijacking or data manipulation.

This guide provides a practical, hands-on methodology for testing unencrypted data transmission, adhering to OWASP’s WSTG-CRYP-03, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing unencrypted data transmission, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts and inspects HTTP traffic for unencrypted data.
- **Wireshark**: Captures and analyzes network traffic for unencrypted sensitive information.
- **Browser Developer Tools**: Identifies mixed content and unencrypted requests.
- **OWASP ZAP**: Automates detection of HTTP traffic and insecure configurations.
- **cURL**: Sends requests to test for HTTP usage and inspect responses.

### **Tool Setup Instructions**

1. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
   - Verify: `curl -x http://127.0.0.1:8080 http://example.com`.
2. **Wireshark**:
   - Download from [wireshark.org](https://www.wireshark.org/).
   - Install on Linux: `sudo apt install wireshark`.
   - Configure capture interface (e.g., `eth0`).
   - Verify: `wireshark --version`.
3. **Browser Developer Tools**:
   - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
   - No setup required.
4. **OWASP ZAP**:
   - Download from [zaproxy.org](https://www.zaproxy.org/download/).
   - Run: `zap.sh` (Linux) or `zap.bat` (Windows).
   - Verify: Check ZAP GUI.
5. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-CRYP-03, focusing on intercepting and analyzing HTTP traffic, form submissions, API calls, cookies, and mixed content to detect sensitive information sent over unencrypted channels.

### **1. Intercept HTTP Traffic with Burp Suite**

Capture and inspect HTTP requests and responses to identify unencrypted sensitive data.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Traffic**:
   - Browse the application, log in, submit forms, or interact with APIs.
   - Check “HTTP History” for HTTP requests (e.g., `http://example.com/login`).
3. **Analyze Requests**:
   - Look for sensitive data (e.g., usernames, passwords, session tokens) in GET/POST parameters, headers, or response bodies.
   - Note endpoints using HTTP instead of HTTPS.
4. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Filter for HTTP requests:
  ```
  HTTP History -> Filter -> Show only: Protocol=HTTP -> Check for sensitive data in requests
  ```
- **Command 2**: Inspect a login request:
  ```
  HTTP History -> Select POST /login -> Send to Repeater -> Check for username/password in body -> Verify Protocol=HTTP
  ```

**Example Vulnerable Request**:
```
POST http://example.com/login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=secret123
```

**Remediation**:
- Enforce HTTPS:
  ```apache
  <VirtualHost *:80>
      ServerName example.com
      Redirect permanent / https://example.com/
  </VirtualHost>
  ```

### **2. Capture Network Traffic with Wireshark**

Analyze network traffic to detect unencrypted sensitive data.

**Steps**:
1. **Configure Wireshark**:
   - Select capture interface (e.g., `eth0`).
   - Apply filter: `http`.
2. **Capture Traffic**:
   - Browse the application or send requests to `http://example.com`.
   - Capture packets during login, form submissions, or API calls.
3. **Analyze Packets**:
   - Look for HTTP packets containing sensitive data (e.g., `username=admin`, `session=abc123`).
   - Check for unencrypted POST bodies or GET parameters.
4. **Document Findings**:
   - Save packet capture (.pcap) and screenshots.

**Wireshark Commands**:
- **Command 1**: Filter HTTP traffic:
  ```
  Capture Filter: http -> Start Capture -> Apply Display Filter: http.request.method == "POST"
  ```
- **Command 2**: Search for sensitive data:
  ```
  Display Filter: http contains "username" -> Right-click packet -> Follow -> HTTP Stream
  ```

**Example Vulnerable Packet**:
```
POST /login HTTP/1.1
Host: example.com
username=admin&password=secret123
```

**Remediation**:
- Enable TLS:
  ```nginx
  server {
      listen 443 ssl;
      server_name example.com;
      ssl_certificate /etc/ssl/certs/example.com.crt;
      ssl_certificate_key /etc/ssl/private/example.com.key;
  }
  ```

### **3. Identify Mixed Content with Browser Developer Tools**

Check for HTTP resources loaded on HTTPS pages, indicating unencrypted data transmission.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Check Console**:
   - Look for mixed content warnings (e.g., “Blocked loading mixed active content”).
3. **Inspect Network Tab**:
   - Verify resources (e.g., scripts, images) loaded via HTTP.
   - Check for sensitive data in responses.
4. **Analyze Findings**:
   - Confirm if HTTP resources expose sensitive information.
   - Expected secure response: All resources use HTTPS.
5. **Document Findings**:
   - Save screenshots and network logs.

**Browser Developer Tools Commands**:
- **Command 1**: Check for mixed content:
  ```
  Console tab -> Look for warnings like "Mixed Content: http://example.com/script.js"
  ```
- **Command 2**: Inspect network resources:
  ```
  Network tab -> Reload page -> Filter by Protocol=HTTP -> Check resource content
  ```

**Example Vulnerable Finding**:
```
Mixed Content: The page at 'https://example.com' loaded 'http://example.com/user_data.js' over HTTP.
```

**Remediation**:
- Use HTTPS for all resources:
  ```html
  <script src="https://example.com/script.js"></script>
  ```

### **4. Automate HTTP Detection with OWASP ZAP**

Use automated scanning to identify unencrypted traffic and insecure configurations.

**Steps**:
1. **Configure OWASP ZAP**:
   - Set proxy to 127.0.0.1:8080.
   - Import target URL (e.g., `http://example.com`).
2. **Run Active Scan**:
   - Scan for HTTP endpoints and insecure data transmission.
   - Check for missing HSTS or insecure cookies.
3. **Analyze Results**:
   - Review Alerts tab for HTTP usage or sensitive data exposure.
   - Verify findings manually with Burp Suite.
4. **Document Findings**:
   - Save ZAP scan reports.

**OWASP ZAP Commands**:
- **Command 1**: Scan for HTTP endpoints:
  ```
  Sites tab -> Right-click http://example.com -> Attack -> Active Scan -> Enable Information Disclosure -> Start Scan
  ```
- **Command 2**: Check for insecure cookies:
  ```
  Sites tab -> Right-click http://example.com -> Report -> Generate HTML Report -> Look for "Cookie No Secure Flag"
  ```

**Example Vulnerable Finding**:
- Alert: `Insecure Transmission - Sensitive data sent over HTTP`.

**Remediation**:
- Set secure cookies:
  ```php
  setcookie('session', 'abc123', ['secure' => true, 'httponly' => true]);
  ```

### **5. Test Endpoints with cURL**

Manually send HTTP requests to verify unencrypted data transmission.

**Steps**:
1. **Identify Endpoints**:
   - Use Burp Suite to find HTTP endpoints (e.g., `http://example.com/login`).
2. **Send Requests**:
   - Use cURL to submit sensitive data over HTTP.
   - Test both GET and POST methods.
3. **Analyze Responses**:
   - Check for sensitive data in requests or responses.
   - Verify if the server accepts HTTP requests.
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Test a login form over HTTP:
  ```bash
  curl -i -X POST -d "username=admin&password=secret123" http://example.com/login
  ```
- **Command 2**: Check for sensitive data in GET request:
  ```bash
  curl -i http://example.com/profile?session=abc123
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"user_id": 123, "email": "admin@example.com"}
```

**Remediation**:
- Redirect HTTP to HTTPS:
  ```nginx
  server {
      listen 80;
      server_name example.com;
      return 301 https://$server_name$request_uri;
  }
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-CRYP-03 with practical scenarios based on common vulnerabilities involving unencrypted data transmission observed in penetration testing.

### **Test 1: Unencrypted Login Form Submission**

**Objective**: Detect sensitive data sent via HTTP during login.

**Steps**:
1. **Capture Login Request**:
   - Use Burp Suite to intercept `POST /login`.
   - Command:
     ```
     HTTP History -> Select POST /login -> Check for username/password in body -> Verify Protocol=HTTP
     ```
2. **Verify with cURL**:
   - Command:
     ```bash
     curl -i -X POST -d "username=admin&password=secret123" http://example.com/login
     ```
3. **Analyze Response**:
   - Check for sensitive data in the request body.
   - Expected secure response: HTTPS enforced, HTTP rejected.
4. **Save Results**:
   - Save Burp Suite and cURL outputs.

**Example Vulnerable Request**:
```
POST http://example.com/login HTTP/1.1
username=admin&password=secret123
```

**Remediation**:
```apache
<VirtualHost *:80>
    Redirect permanent / https://example.com/
</VirtualHost>
```

### **Test 2: Unencrypted API Data Exposure**

**Objective**: Detect sensitive data returned over HTTP by an API.

**Steps**:
1. **Capture API Request**:
   - Use Burp Suite to find `GET /api/user`.
   - Command:
     ```
     HTTP History -> Select GET /api/user -> Check response for sensitive data -> Verify Protocol=HTTP
     ```
2. **Verify with cURL**:
   - Command:
     ```bash
     curl -i http://example.com/api/user?session=abc123
     ```
3. **Analyze Response**:
   - Check for sensitive data (e.g., email, user ID) in the response.
   - Expected secure response: HTTPS only.
4. **Save Results**:
   - Save Burp Suite and cURL outputs.

**Example Vulnerable Response**:
```json
{
  "user_id": 123,
  "email": "admin@example.com"
}
```

**Remediation**:
```nginx
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;
}
```

### **Test 3: Mixed Content on HTTPS Page**

**Objective**: Identify HTTP resources loaded on an HTTPS page.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12`.
2. **Check Console**:
   - Command:
     ```
     Console tab -> Look for "Mixed Content" warnings
     ```
3. **Inspect Network Tab**:
   - Command:
     ```
     Network tab -> Filter by Protocol=HTTP -> Check resource content
     ```
4. **Analyze Findings**:
   - Verify if HTTP resources contain sensitive data.
   - Expected secure response: All HTTPS resources.
5. **Save Results**:
   - Save screenshots.

**Example Vulnerable Finding**:
```
Mixed Content: http://example.com/user_data.js
```

**Remediation**:
```html
<script src="https://example.com/user_data.js"></script>
```

### **Test 4: Insecure Cookie Transmission**

**Objective**: Detect cookies sent over HTTP due to missing `Secure` flags.

**Steps**:
1. **Capture Cookies**:
   - Use Burp Suite to inspect `Set-Cookie` headers.
   - Command:
     ```
     HTTP History -> Select response with Set-Cookie -> Check for Secure flag
     ```
2. **Test with OWASP ZAP**:
   - Command:
     ```
     Sites tab -> Right-click http://example.com -> Report -> Generate HTML Report -> Look for "Cookie No Secure Flag"
     ```
3. **Analyze Findings**:
   - Verify if cookies are transmitted over HTTP.
   - Expected secure response: `Secure` flag present.
4. **Save Results**:
   - Save Burp Suite and ZAP outputs.

**Example Vulnerable Header**:
```
Set-Cookie: session=abc123; Path=/
```

**Remediation**:
```php
setcookie('session', 'abc123', ['secure' => true, 'httponly' => true]);
```

## **Additional Tips**

- **Test All Endpoints**: Check forms, APIs, and static resources for HTTP usage.
- **Combine Tools**: Use Burp Suite for manual inspection, Wireshark for network analysis, and OWASP ZAP for automation.
- **Gray-Box Testing**: If documentation is available, verify server configurations or HSTS policies.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for traffic interception, as capturing sensitive data may have legal implications.
- **References**: [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html), [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/).