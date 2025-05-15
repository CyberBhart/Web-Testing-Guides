# **Testing for Stack Traces**

## **Overview**

Testing for stack traces (WSTG-ERRH-02) involves assessing whether a web application or server exposes detailed error messages, known as stack traces, when encountering errors. According to OWASP, stack traces can reveal sensitive information, such as file paths, function names, database queries, or software versions, which attackers can exploit for reconnaissance or targeted attacks. This test focuses on provoking errors through invalid inputs, malformed requests, or unexpected conditions and analyzing responses for stack traces that indicate insecure error handling.

**Impact**: Stack trace exposure can lead to:
- Disclosure of system internals (e.g., file paths, framework versions).
- Facilitation of attack chaining (e.g., exploiting exposed database queries for SQL injection).
- Identification of vulnerable components (e.g., outdated libraries).
- Increased attack surface by revealing application logic or server configurations.

This guide provides a practical, hands-on methodology for testing stack trace vulnerabilities, adhering to OWASP’s WSTG-ERRH-02, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing stack trace vulnerabilities, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to trigger errors.
- **cURL**: Sends malformed or invalid requests to provoke stack traces.
- **Postman**: Tests API endpoints with invalid inputs to elicit detailed error responses.
- **Browser Developer Tools**: Inspects and modifies requests to analyze error handling.
- **OWASP ZAP**: Automates detection of stack traces through fuzzing and scanning.

### **Tool Setup Instructions**

1. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
   - Verify: Start Burp and check proxy with `curl -x http://127.0.0.1:8080 http://example.com`.
2. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
3. **Postman**:
   - Download from [postman.com](https://www.postman.com/downloads/).
   - Install and create a free account.
   - Verify: Open Postman and check version.
4. **Browser Developer Tools**:
   - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
   - No setup required.
5. **OWASP ZAP**:
   - Download from [zaproxy.org](https://www.zaproxy.org/download/).
   - Run: `zap.sh` (Linux) or `zap.bat` (Windows).
   - Verify: Check ZAP GUI.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-ERRH-02, focusing on triggering errors through invalid inputs, malformed requests, or unauthorized actions and analyzing responses for stack traces or sensitive debug information.

### **1. Trigger Application Errors with Burp Suite**

Provoke errors by sending invalid inputs to application input points to elicit stack traces.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Input Points**:
   - Browse the application to identify forms, search fields, or API endpoints.
   - Capture requests in Burp Suite’s “HTTP History” (e.g., `POST /search`, `GET /profile?id=1`).
3. **Manipulate Inputs**:
   - Use Burp Repeater to send invalid data (e.g., strings in integer fields, special characters).
   - Test for unhandled exceptions or debug output.
4. **Analyze Response**:
   - Check for HTTP 500, stack traces, or sensitive details (e.g., file paths, function names).
   - Look for errors in HTTP 200 responses or redirects.
5. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Send invalid input to a parameter:
  ```
  HTTP History -> Select GET /profile?id=1 -> Send to Repeater -> Change id to id=abc -> Click Send -> Check Response for stack traces
  ```
- **Command 2**: Test form submission with malformed data:
  ```
  HTTP History -> Select POST /search -> Send to Repeater -> Change q=test to q=%27%20OR%201=1%20-- -> Click Send -> Inspect Response for debug info
  ```

**Example Request**:
```
GET /profile?id=abc HTTP/1.1
Host: example.com
Cookie: session=abc123
```

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Content-Type: text/html
Traceback (most recent call last):
  File "/var/www/app/index.php", line 45, in handleRequest
    $id = (int)$_GET['id'];
TypeError: Invalid type 'abc' for id
```

**Remediation**:
- Handle exceptions gracefully:
  ```php
  try {
      $id = (int)$_GET['id'];
      $result = $db->query("SELECT * FROM users WHERE id = $id");
  } catch (Exception $e) {
      http_response_code(400);
      die('Invalid request');
  }
  ```

### **2. Trigger Server Errors with cURL**

Send malformed HTTP requests to provoke server-level stack traces.

**Steps**:
1. **Identify Endpoints**:
   - Use Burp Suite to find URLs (e.g., `/index.php`, `/api/v1/users`).
   - Test nonexistent or invalid paths (e.g., `/invalid.php`).
2. **Send Malformed Requests**:
   - Use cURL to send invalid HTTP methods, headers, or URLs.
   - Test for HTTP 500, 404, or 400 errors with debug output.
3. **Analyze Response**:
   - Check for stack traces, server banners (e.g., Apache 2.4.41), or file paths.
   - Verify if errors expose system details.
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Request an invalid resource:
  ```bash
  curl -i http://example.com/invalid.php
  ```
- **Command 2**: Send a malformed HTTP request:
  ```bash
  curl -i -H "Invalid-Header: %%%" -X GET http://example.com/index.php
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html
Fatal error: Uncaught Exception in /var/www/html/server.php:123
Stack trace:
#0 /var/www/html/index.php(45): handleRequest()
```

**Remediation**:
- Suppress stack traces:
  ```apache
  ErrorDocument 500 /error.html
  php_flag display_errors Off
  ```

### **3. Test API Stack Traces with Postman**

Provoke stack traces in API endpoints by sending invalid or malicious inputs.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find APIs (e.g., `/api/v1/users`).
   - Import into Postman.
2. **Send Invalid Requests**:
   - Send malformed JSON, invalid parameters, or special characters.
   - Test with and without authentication.
3. **Analyze Response**:
   - Check for HTTP 500, stack traces, or debug details (e.g., code line numbers).
   - Verify if errors appear in JSON responses.
4. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Send malformed JSON to an API:
  ```
  New Request -> POST http://example.com/api/v1/users -> Body -> raw -> JSON: {"name": "test", "age": "abc -> Headers: Authorization: Bearer abc123 -> Send
  ```
- **Command 2**: Test invalid parameter type:
  ```
  New Request -> GET http://example.com/api/v1/profile?id=abc -> Headers: Authorization: Bearer abc123 -> Send
  ```

**Example Vulnerable API Response**:
```json
{
  "error": "Traceback (most recent call last):\n  File \"/app/controllers/user.py\", line 67, in getUser\n    id = int(id)\nValueError: invalid literal for int() with base 10: 'abc'"
}
```

**Remediation**:
- Avoid debug output in APIs:
  ```javascript
  app.post('/api/v1/users', (req, res) => {
      try {
          const age = parseInt(req.body.age);
          if (isNaN(age)) throw new Error('Invalid age');
          res.json({ status: 'success' });
      } catch (e) {
          res.status(400).json({ error: 'Invalid request' });
      }
  });
  ```

### **4. Manipulate Requests with Browser Developer Tools**

Modify form submissions or requests to trigger stack traces.

**Steps**:
1. **Inspect Input Points**:
   - Open Developer Tools (`F12`) on a form page (e.g., `http://example.com/search`).
   - Identify input fields and their expected types.
2. **Manipulate Inputs**:
   - Edit form data (e.g., change a number to a string) before submission.
   - Modify query parameters in URLs.
3. **Analyze Response**:
   - Check for stack traces, HTTP 500, or debug details in the DOM or network responses.
   - Verify if errors expose code or system information.
4. **Document Findings**:
   - Save screenshots and network logs.

**Browser Developer Tools Commands**:
- **Command 1**: Modify form input to trigger an error:
  ```
  Elements tab -> Find <input name="id" type="number"> -> Edit as HTML -> Change value to "abc" -> Submit form
  ```
- **Command 2**: Edit query parameter in a request:
  ```
  Network tab -> Right-click GET /profile?id=1 -> Copy as cURL -> Modify id=abc -> Replay in terminal
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Content-Type: text/html
StackTrace: /var/www/app/index.php:123 in UserController->getProfile()
```

**Remediation**:
- Validate inputs client-side and server-side:
  ```html
  <form onsubmit="return validate()">
      <input type="number" name="id" required>
      <script>
          function validate() {
              const id = document.querySelector('[name="id"]').value;
              if (!/^\d+$/.test(id)) {
                  alert('Invalid ID');
                  return false;
              }
              return true;
          }
      </script>
  </form>
  ```

### **5. Automate Stack Trace Detection with OWASP ZAP**

Use automated scanning to identify stack traces in error responses.

**Steps**:
1. **Configure OWASP ZAP**:
   - Set proxy to 127.0.0.1:8080.
   - Import target URL (e.g., `http://example.com`).
2. **Run Fuzzing Scan**:
   - Fuzz input parameters with invalid data (e.g., strings, special characters).
   - Scan for stack traces or debug output.
3. **Analyze Results**:
   - Check Alerts tab for information disclosure or stack trace issues.
   - Verify findings manually with Burp Suite.
4. **Document Findings**:
   - Save ZAP scan reports.

**OWASP ZAP Commands**:
- **Command 1**: Fuzz a parameter for stack traces:
  ```
  Sites tab -> Right-click GET http://example.com/profile?id=1 -> Attack -> Fuzzer -> Add Payloads: Strings (e.g., abc, %27) -> Start Fuzzer -> Check Responses
  ```
- **Command 2**: Run active scan for debug errors:
  ```
  Sites tab -> Right-click http://example.com -> Attack -> Active Scan -> Enable Information Disclosure -> Start Scan -> Check Alerts
  ```

**Example Vulnerable Finding**:
- Alert: `Information Disclosure - Stack Trace` with details: `File "/app/user.py", line 45`.

**Remediation**:
- Disable debug mode:
  ```python
  app = Flask(__name__)
  app.config['DEBUG'] = False
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-ERRH-02 with practical scenarios based on common stack trace vulnerabilities observed in penetration testing.

### **Test 1: Invalid Form Input Stack Trace**

**Objective**: Trigger a stack trace by sending invalid form data.

**Steps**:
1. **Identify Form**:
   - Use Burp Suite to capture a form submission (e.g., `POST /profile`).
2. **Manipulate Input**:
   - Command:
     ```
     HTTP History -> Select POST /profile -> Send to Repeater -> Change age=25 to age=abc -> Click Send
     ```
3. **Analyze Response**:
   - Check for HTTP 500 or stack traces with file paths or code details.
   - Expected secure response: Generic error (e.g., `Invalid input`).
4. **Save Results**:
   - Save Burp Repeater response.

**Command**:
```bash
curl -X POST -d "age=abc" -b "session=abc123" http://example.com/profile
```

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Traceback (most recent call last):
  File "/app/profile.py", line 32, in updateProfile
    age = int(request.form['age'])
ValueError: invalid literal for int() with base 10: 'abc'
```

**Remediation**:
```python
from flask import Flask, request
app = Flask(__name__)
@app.route('/profile', methods=['POST'])
def profile():
    try:
        age = int(request.form['age'])
        return jsonify({'status': 'success'})
    except ValueError:
        return jsonify({'error': 'Invalid age'}), 400
```

### **Test 2: Nonexistent Resource Stack Trace**

**Objective**: Provoke a stack trace by requesting an invalid resource.

**Steps**:
1. **Send Request**:
   - Command:
     ```bash
     curl -i http://example.com/invalid.php
     ```
2. **Analyze Response**:
   - Check for HTTP 500 or stack traces with server details.
   - Expected secure response: Custom error page.
3. **Save Results**:
   - Save response to file.

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Server: Apache/2.4.41
Fatal error: Uncaught Error: Call to undefined function in /var/www/html/invalid.php:10
Stack trace:
#0 {main}
```

**Remediation**:
```nginx
error_page 500 /custom_error.html;
server_tokens off;
```

### **Test 3: API Malformed JSON Stack Trace**

**Objective**: Trigger a stack trace in an API with invalid JSON.

**Steps**:
1. **Set Up Postman**:
   - Create request: `POST http://example.com/api/v1/users`.
2. **Send Malformed JSON**:
   - Command: In Postman, set body to `{"name": "test", "age": "abc` and send.
3. **Analyze Response**:
   - Check for stack traces or debug details.
   - Expected secure response: HTTP 400 with generic message.
4. **Save Results**:
   - Export Postman response.

**Command**:
```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer abc123" --data '{"name": "test", "age": "abc' http://example.com/api/v1/users
```

**Example Vulnerable Response**:
```json
{
  "error": "SyntaxError: Unexpected end of JSON input at /app/api/users.js:23"
}
```

**Remediation**:
```javascript
const express = require('express');
const app = express();
app.use(express.json());
app.post('/api/v1/users', (req, res) => {
    try {
        const { name, age } = req.body;
        res.json({ status: 'success' });
    } catch (e) {
        res.status(400).json({ error: 'Invalid JSON' });
    }
});
```

### **Test 4: Malformed HTTP Header Stack Trace**

**Objective**: Provoke a stack trace with invalid HTTP headers.

**Steps**:
1. **Send Malformed Request**:
   - Command:
     ```bash
     curl -i -H "Invalid-Header: %%%" http://example.com/index.php
     ```
2. **Analyze Response**:
   - Check for HTTP 500 or stack traces with server details.
   - Expected secure response: Generic error.
3. **Save Results**:
   - Save response.

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Server: IIS/10.0
StackTrace: at System.Web.HttpRequest.ValidateHeader(String name) in c:\inetpub\wwwroot\request.cs:89
```

**Remediation**:
```apache
<IfModule mod_headers.c>
    Header unset Invalid-Header
</IfModule>
```

## **Additional Tips**

- **Map Input Points**: Test all forms, APIs, and URLs to identify stack trace vulnerabilities.
- **Combine Tools**: Use Burp Suite for manual testing, OWASP ZAP for automation, and cURL for server-level tests.
- **Gray-Box Testing**: If documentation is available, check for debug settings or error logging mechanisms.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for active testing to avoid disrupting live systems.
- **References**: [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html), [OWASP Proactive Controls C10](https://owasp.org/www-project-proactive-controls/v3/en/c10-handle-errors).