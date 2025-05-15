# **Testing for Improper Error Handling**

## **Overview**

Testing for improper error handling (WSTG-ERRH-01) involves assessing how a web application or server responds to errors triggered by invalid inputs, malformed requests, or unexpected conditions. According to OWASP, improper error handling can expose sensitive information, such as stack traces, database queries, file paths, or software versions, which attackers can use for reconnaissance or to chain attacks. This test focuses on provoking errors through various inputs (e.g., forms, APIs, URLs) and analyzing responses to identify leakage of sensitive data or insecure error handling practices.

**Impact**: Improper error handling can lead to:
- Exposure of system details (e.g., framework versions, database types).
- Facilitation of attack chaining (e.g., SQL injection from exposed queries).
- User confusion or application instability due to unhandled exceptions.
- Increased attack surface by revealing internal logic or misconfigurations.

This guide provides a practical, hands-on methodology for testing improper error handling, adhering to OWASP’s WSTG-ERRH-01, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing improper error handling, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to trigger errors.
- **cURL**: Sends malformed or invalid requests to provoke server/application errors.
- **Postman**: Tests API endpoints with invalid inputs to elicit error responses.
- **Browser Developer Tools**: Inspects and modifies requests to analyze error handling.
- **OWASP ZAP**: Automates error detection through fuzzing and scanning.

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

This methodology follows OWASP’s black-box approach for WSTG-ERRH-01, focusing on triggering errors through invalid inputs, malformed requests, and unauthorized actions, then analyzing responses for sensitive information.

### **1. Trigger Application Errors with Burp Suite**

Provoke errors by sending invalid inputs to application input points (e.g., forms, query parameters).

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Input Points**:
   - Browse the application to identify forms, search fields, or API endpoints.
   - Capture requests in Burp Suite’s “HTTP History” (e.g., `POST /search`, `GET /profile?id=1`).
3. **Manipulate Inputs**:
   - Use Burp Repeater to modify parameters (e.g., send a string to an integer field).
   - Test for errors like stack traces or database errors.
4. **Analyze Response**:
   - Check for HTTP 500, verbose error messages, or sensitive data (e.g., SQL queries, file paths).
   - Note if errors appear in HTTP 200 responses or redirects.
5. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Send invalid input to a search parameter:
  ```
  HTTP History -> Select GET /search?q=test -> Send to Repeater -> Modify q to q=abc' OR 1=1 -- -> Click Send -> Check Response for errors
  ```
- **Command 2**: Test integer parameter with a string:
  ```
  HTTP History -> Select GET /profile?id=1 -> Send to Repeater -> Change id to id=abc -> Click Send -> Inspect Response for stack traces
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
Error: Invalid integer value 'abc' in query: SELECT * FROM users WHERE id = abc
```

**Remediation**:
- Implement generic error handling:
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

Send malformed HTTP requests to provoke server-level errors.

**Steps**:
1. **Identify Endpoints**:
   - Use Burp Suite to find URLs (e.g., `/index.php`, `/api/v1/users`).
   - Test nonexistent paths (e.g., `/nonexistent`).
2. **Send Malformed Requests**:
   - Use cURL to send invalid HTTP methods, headers, or oversized URLs.
   - Test for HTTP 404, 403, or 500 errors.
3. **Analyze Response**:
   - Check for verbose error pages, server banners (e.g., Apache 2.4.41), or stack traces.
   - Verify if errors expose system details.
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Request a nonexistent resource:
  ```bash
  curl -i http://example.com/nonexistent
  ```
- **Command 2**: Send an invalid HTTP method:
  ```bash
  curl -i -X INVALID http://example.com/index.php -H "Cookie: session=abc123"
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 404 Not Found
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html
Error: File /var/www/html/nonexistent not found
```

**Remediation**:
- Configure custom error pages:
  ```apache
  ErrorDocument 404 /error.html
  ErrorDocument 500 /error.html
  ```

### **3. Test API Error Handling with Postman**

Provoke errors in API endpoints by sending invalid or malicious inputs.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find APIs (e.g., `/api/v1/users`).
   - Import into Postman.
2. **Send Invalid Requests**:
   - Send malformed JSON, invalid parameters, or oversized data.
   - Test with and without authentication.
3. **Analyze Response**:
   - Check for HTTP 400/500, stack traces, or database errors.
   - Verify if errors expose internal logic.
4. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Send malformed JSON to an API:
  ```
  New Request -> POST http://example.com/api/v1/users -> Body -> raw -> JSON: {"name": "test", "age": "abc -> Headers: Cookie: session=abc123 -> Send
  ```
- **Command 2**: Test invalid parameter type:
  ```
  New Request -> GET http://example.com/api/v1/profile?id=abc -> Headers: Authorization: Bearer abc123 -> Send
  ```

**Example Vulnerable API Response**:
```json
{
  "error": "TypeError: Cannot cast 'abc' to Integer in /app/models/user.js:45"
}
```

**Remediation**:
- Sanitize API inputs:
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

Modify form submissions or requests to trigger errors.

**Steps**:
1. **Inspect Input Points**:
   - Open Developer Tools (`F12`) on a form page (e.g., `http://example.com/search`).
   - Identify input fields and their expected types.
2. **Manipulate Inputs**:
   - Edit form data (e.g., change a number to a string) before submission.
   - Modify query parameters in URLs.
3. **Analyze Response**:
   - Check for verbose errors, HTTP 500, or redirects with error details.
   - Verify if errors appear in the DOM or network responses.
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
Error: Invalid input at /var/www/app/index.php:123
```

**Remediation**:
- Validate form inputs:
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

### **5. Automate Error Detection with OWASP ZAP**

Use automated scanning to identify improper error handling.

**Steps**:
1. **Configure OWASP ZAP**:
   - Set proxy to 127.0.0.1:8080.
   - Import target URL (e.g., `http://example.com`).
2. **Run Fuzzing Scan**:
   - Fuzz input parameters with invalid data (e.g., strings, special characters).
   - Scan for verbose errors or stack traces.
3. **Analyze Results**:
   - Check Alerts tab for information disclosure or error-related issues.
   - Verify findings manually with Burp Suite.
4. **Document Findings**:
   - Save ZAP scan reports.

**OWASP ZAP Commands**:
- **Command 1**: Fuzz a search parameter:
  ```
  Sites tab -> Right-click GET http://example.com/search?q=test -> Attack -> Fuzzer -> Add Payloads: Strings (e.g., abc, ' OR 1=1 --) -> Start Fuzzer -> Check Responses
  ```
- **Command 2**: Run active scan for error handling:
  ```
  Sites tab -> Right-click http://example.com -> Attack -> Active Scan -> Enable Information Disclosure -> Start Scan -> Check Alerts
  ```

**Example Vulnerable Finding**:
- Alert: `Information Disclosure - Debug Error Message` with stack trace.

**Remediation**:
- Disable debug output:
  ```python
  app = Flask(__name__)
  app.config['DEBUG'] = False
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-ERRH-01 with practical scenarios based on common improper error handling vulnerabilities observed in penetration testing.

### **Test 1: Invalid Form Input Error**

**Objective**: Trigger an error by sending invalid form data.

**Steps**:
1. **Identify Form**:
   - Use Burp Suite to capture a form submission (e.g., `POST /search`).
2. **Manipulate Input**:
   - Command:
     ```
     HTTP History -> Select POST /search -> Send to Repeater -> Change q=test to q=abc' OR 1=1 -- -> Click Send
     ```
3. **Analyze Response**:
   - Check for HTTP 500 or SQL error messages.
   - Expected secure response: Generic error (e.g., `Invalid input`).
4. **Save Results**:
   - Save Burp Repeater response.

**Command**:
```bash
curl -X POST -d "q=abc%27%20OR%201=1%20--" -b "session=abc123" http://example.com/search
```

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Error: You have an error in your SQL syntax near 'abc' OR 1=1 --'
```

**Remediation**:
```php
$q = filter_input(INPUT_POST, 'q', FILTER_SANITIZE_STRING);
if (!$q) {
    http_response_code(400);
    die('Invalid search query');
}
```

### **Test 2: Nonexistent Resource Error**

**Objective**: Provoke a server error by requesting a nonexistent resource.

**Steps**:
1. **Send Request**:
   - Command:
     ```bash
     curl -i http://example.com/nonexistent
     ```
2. **Analyze Response**:
   - Check for HTTP 404 with server details (e.g., Apache version).
   - Expected secure response: Custom error page.
3. **Save Results**:
   - Save response to file.

**Example Vulnerable Response**:
```
HTTP/1.1 404 Not Found
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html
Error: File /var/www/html/nonexistent not found
```

**Remediation**:
```nginx
error_page 404 /custom_404.html;
server_tokens off;
```

### **Test 3: API Invalid Parameter Error**

**Objective**: Trigger an API error with invalid parameters.

**Steps**:
1. **Set Up Postman**:
   - Create request: `GET http://example.com/api/v1/profile?id=abc`.
2. **Send Request**:
   - Command: In Postman, send request with `id=abc`.
3. **Analyze Response**:
   - Check for stack traces or database errors.
   - Expected secure response: HTTP 400 with generic message.
4. **Save Results**:
   - Export Postman response.

**Command**:
```bash
curl -i -H "Authorization: Bearer abc123" http://example.com/api/v1/profile?id=abc
```

**Example Vulnerable Response**:
```json
{
  "error": "TypeError: Invalid id at /app/controllers/profile.js:67"
}
```

**Remediation**:
```python
from flask import Flask, request
app = Flask(__name__)
@app.route('/api/v1/profile')
def profile():
    try:
        id = int(request.args.get('id'))
        return jsonify(db.get_profile(id))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid ID'}), 400
```

### **Test 4: Malformed HTTP Request Error**

**Objective**: Provoke a server error with an invalid HTTP request.

**Steps**:
1. **Send Malformed Request**:
   - Command:
     ```bash
     curl -i -X INVALID http://example.com/index.php -H "Cookie: session=abc123"
     ```
2. **Analyze Response**:
   - Check for HTTP 400/500 with server details.
   - Expected secure response: Generic error.
3. **Save Results**:
   - Save response.

**Example Vulnerable Response**:
```
HTTP/1.1 400 Bad Request
Server: IIS/10.0
Error: Invalid HTTP method
```

**Remediation**:
```apache
<IfModule mod_rewrite.c>
    RewriteCond %{REQUEST_METHOD} !^(GET|POST|HEAD|PUT|DELETE|OPTIONS)
    RewriteRule .* - [R=400,L]
</IfModule>
```

## **Additional Tips**

- **Map Input Points**: Identify all forms, APIs, and URLs to test comprehensively.
- **Combine Tools**: Use Burp Suite for manual testing, OWASP ZAP for automation, and cURL for quick server tests.
- **Gray-Box Testing**: If documentation is available, check for error handling configurations or logging mechanisms.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for active testing to avoid disrupting live systems.
- **References**: [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html), [OWASP Proactive Controls C10](https://owasp.org/www-project-proactive-controls/v3/en/c10-handle-errors).