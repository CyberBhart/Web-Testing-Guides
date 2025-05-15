# **Testing for Cookies Attributes**

## **Overview**

Testing for Cookies Attributes (WSTG-SESS-02) involves assessing the security configuration of session cookies in a web application to ensure they are protected against unauthorized access, interception, or manipulation. According to OWASP, misconfigured cookie attributes can lead to vulnerabilities such as session hijacking, cross-site scripting (XSS), or cross-site request forgery (CSRF). This test focuses on verifying the presence and correctness of `HttpOnly`, `Secure`, `SameSite`, expiration, and scope attributes, as well as ensuring cookies do not contain sensitive data, to mitigate risks in session management.

**Impact**: Misconfigured cookie attributes can lead to:
- Session hijacking by intercepting cookies over unencrypted connections.
- Cookie theft through XSS attacks due to missing `HttpOnly` flags.
- CSRF attacks or unintended cookie sharing due to lax `SameSite` settings.
- Persistent sessions from missing or overly long expiration times, increasing exposure.

This guide provides a practical, hands-on methodology for testing cookie attributes, adhering to OWASP’s WSTG-SESS-02, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing cookie attributes, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts and analyzes cookies for secure attributes and transmission.
- **Postman**: Tests API responses for cookie settings and behavior.
- **cURL**: Sends requests to inspect cookie headers and attributes.
- **Browser Developer Tools**: Inspects cookies, their attributes, and client-side accessibility.
- **Python Requests Library**: Automates cookie collection and analysis for attributes and content.

### **Tool Setup Instructions**

1. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
   - Verify: `curl -x http://127.0.0.1:8080 http://example.com`.
2. **Postman**:
   - Download from [postman.com](https://www.postman.com/downloads/).
   - Install and create a free account.
   - Verify: Open Postman and check version.
3. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
4. **Browser Developer Tools**:
   - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
   - No setup required.
5. **Python Requests Library**:
   - Install Python: `sudo apt install python3`.
   - Install Requests: `pip install requests`.
   - Verify: `python3 -c "import requests; print(requests.__version__)"`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-SESS-02, focusing on testing `HttpOnly`, `Secure`, `SameSite`, expiration, scope, and content of session cookies.

### **1. Inspect Cookie Attributes with Burp Suite**

Analyze session cookies for `HttpOnly`, `Secure`, and `SameSite` attributes.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Login Response**:
   - Log in to the application and check “HTTP History” for the `Set-Cookie` header in the response.
   - Note the session cookie (e.g., `session=abc123`).
3. **Inspect Attributes**:
   - Verify presence of `HttpOnly`, `Secure`, and `SameSite` (preferably `Strict` or `Lax`).
   - Check `Expires` or `Max-Age` for reasonable session duration (e.g., 30 minutes).
   - Ensure `Path` and `Domain` are appropriately scoped (e.g., `Path=/`, `Domain=example.com`).
4. **Analyze Findings**:
   - Missing attributes or overly broad scope indicate vulnerabilities.
   - Expected secure response: `Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Max-Age=1800; Path=/`.
5. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Inspect cookie attributes:
  ```
  HTTP History -> Select POST /login -> Response tab -> Find Set-Cookie: session=abc123; Path=/ -> Check for HttpOnly, Secure, SameSite
  ```
- **Command 2**: Check cookie scope:
  ```
  HTTP History -> Select POST /login -> Response tab -> Find Set-Cookie -> Verify Path=/ and Domain=example.com
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Set-Cookie: session=abc123; Path=/
```

**Remediation**:
- Set secure cookie attributes:
  ```javascript
  app.use(session({
      secret: 'secure-secret',
      cookie: {
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
          maxAge: 1800000, // 30 minutes
          path: '/',
          domain: 'example.com'
      }
  }));
  ```

### **2. Test HttpOnly Protection with Browser Developer Tools**

Verify that session cookies are inaccessible to client-side scripts.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Inspect Cookies**:
   - Go to “Application” tab (Chrome) or “Storage” tab (Firefox) -> Cookies -> Check `session` cookie attributes.
   - Verify `HttpOnly` is checked.
3. **Test JavaScript Access**:
   - Run `document.cookie` in the “Console” tab to check if the session cookie is accessible.
   - Expected secure response: Cookie not visible (empty or missing `session`).
4. **Analyze Findings**:
   - If `session=abc123` appears, the `HttpOnly` flag is missing.
5. **Document Findings**:
   - Save screenshots and console output.

**Browser Developer Tools Commands**:
- **Command 1**: Check HttpOnly flag:
  ```
  Application tab -> Cookies -> https://example.com -> Select session cookie -> Verify HttpOnly checkbox
  ```
- **Command 2**: Test JavaScript access:
  ```
  Console tab -> Run: document.cookie -> Check if session=abc123 is returned
  ```

**Example Vulnerable Output**:
```
document.cookie
"session=abc123"
```

**Remediation**:
- Enable `HttpOnly` flag:
  ```python
  from flask import Flask, make_response
  app = Flask(__name__)
  @app.route('/login')
  def login():
      response = make_response({'status': 'success'})
      response.set_cookie('session', 'abc123', httponly=True)
      return response
  ```

### **3. Test Secure Flag with cURL**

Ensure session cookies are only transmitted over HTTPS.

**Steps**:
1. **Log In and Capture Cookie**:
   - Log in to capture the session cookie (e.g., `session=abc123`).
   - Use Burp Suite to note the `Set-Cookie` header.
2. **Test HTTP Transmission**:
   - Send a request over HTTP to a protected resource (e.g., `/dashboard`).
   - Check if the session cookie is included in the request.
3. **Analyze Responses**:
   - If the cookie is sent over HTTP, the `Secure` flag is missing.
   - Expected secure response: Cookie not sent; HTTP 401 or redirect to HTTPS.
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Test HTTP request:
  ```bash
  curl -i -b "session=abc123" http://example.com/dashboard
  ```
- **Command 2**: Compare HTTPS request:
  ```bash
  curl -i -b "session=abc123" https://example.com/dashboard
  ```

**Example Vulnerable Response**:
```
[HTTP request]
HTTP/1.1 200 OK
Content-Type: text/html
Dashboard Content
```

**Remediation**:
- Enable `Secure` flag:
  ```javascript
  res.cookie('session', 'abc123', {
      secure: true,
      httpOnly: true,
      sameSite: 'strict'
  });
  ```

### **4. Test SameSite Protection with Postman**

Verify that the `SameSite` attribute mitigates CSRF and cross-site attacks.

**Steps**:
1. **Identify Protected Endpoint**:
   - Use Burp Suite to find a state-changing endpoint (e.g., `POST /update-profile`).
   - Import into Postman.
2. **Simulate Cross-Site Request**:
   - Send a request from a different origin (e.g., `evil.com`) with the session cookie.
   - Use Postman to mimic a cross-site POST request.
3. **Analyze Responses**:
   - Check if the request succeeds with the cookie.
   - Expected secure response: Cookie not sent if `SameSite=Strict`; HTTP 401 or 403.
   - If `SameSite=Lax`, verify only safe methods (e.g., GET) include the cookie.
4. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Test cross-site POST:
  ```
  New Request -> POST http://example.com/update-profile -> Body -> JSON: {"name": "test"} -> Headers: Cookie: session=abc123 -> Send
  ```
- **Command 2**: Test cross-site GET:
  ```
  New Request -> GET http://example.com/profile -> Headers: Cookie: session=abc123 -> Send
  ```

**Example Vulnerable Response**:
```
[Cross-site POST]
HTTP/1.1 200 OK
{"status": "Profile updated"}
```

**Remediation**:
- Set `SameSite=Strict`:
  ```python
  @app.route('/login')
  def login():
      response = make_response({'status': 'success'})
      response.set_cookie('session', 'abc123', httponly=True, secure=True, samesite='Strict')
      return response
  ```

### **5. Analyze Cookie Content and Expiration with Python Requests**

Check cookie expiration times and ensure no sensitive data is stored in cookies.

**Steps**:
1. **Write Python Script**:
   - Create a script to collect and analyze cookies:
     ```python
     import requests
     import base64

     url = 'http://example.com/login'
     response = requests.post(url, data={'username': 'test', 'password': 'Secure123'})
     cookies = response.cookies
     for cookie in cookies:
         print(f"Cookie: {cookie.name}, Value: {cookie.value}")
         print(f"HttpOnly: {cookie.get_nonstandard_attr('HttpOnly', 'Not Set')}")
         print(f"Secure: {cookie.secure}")
         print(f"SameSite: {cookie.get_nonstandard_attr('SameSite', 'Not Set')}")
         print(f"Expires/Max-Age: {cookie.expires or cookie.get_nonstandard_attr('Max-Age', 'Not Set')}")
         # Check for sensitive data
         try:
             decoded = base64.b64decode(cookie.value).decode()
             print(f"Decoded: {decoded}")
             if 'password' in decoded.lower() or 'token' in decoded.lower():
                 print("Warning: Sensitive data in cookie")
         except:
             print("Not base64-encoded")
     ```
2. **Run Script**:
   - Execute: `python3 test_cookie_attributes.py`.
   - Analyze cookies for attributes, expiration, and content.
3. **Verify Findings**:
   - Check if `Max-Age` is reasonable (e.g., 1800 seconds).
   - Ensure no sensitive data (e.g., passwords, tokens) is stored.
   - Expected secure response: Random session ID, reasonable expiration, no sensitive data.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run cookie analysis:
  ```bash
  python3 test_cookie_attributes.py
  ```
- **Command 2**: Test single cookie:
  ```bash
  python3 -c "import requests; r=requests.post('http://example.com/login', data={'username': 'test', 'password': 'Secure123'}); print(r.cookies.get('session'))"
  ```

**Example Vulnerable Output**:
```
Cookie: session, Value: username=test;password=Secure123
Decoded: username=test;password=Secure123
Warning: Sensitive data in cookie
Expires/Max-Age: Not Set
```

**Remediation**:
- Store session data server-side:
  ```javascript
  app.use(session({
      secret: 'secure-secret',
      cookie: {
          maxAge: 1800000, // 30 minutes
          httpOnly: true,
          secure: true,
          sameSite: 'strict'
      },
      store: new MemoryStore() // Use secure session store
  }));
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-SESS-02 with practical scenarios based on common cookie attribute vulnerabilities observed in penetration testing.

### **Test 1: Missing HttpOnly Flag**

**Objective**: Verify that cookies are protected from JavaScript access.

**Steps**:
1. **Capture Cookie**:
   - Use Burp Suite to intercept `POST /login`.
   - Command:
     ```
     HTTP History -> Select POST /login -> Response tab -> Find Set-Cookie: session=abc123
     ```
2. **Test JavaScript Access**:
   - Use Browser Developer Tools:
     ```
     Console tab -> Run: document.cookie -> Check if session=abc123 is returned
     ```
3. **Analyze Response**:
   - If cookie is accessible, `HttpOnly` is missing.
   - Expected secure response: Empty `document.cookie`.
4. **Save Results**:
   - Save Burp Suite and screenshots.

**Example Vulnerable Output**:
```
document.cookie
"session=abc123"
```

**Remediation**:
```javascript
res.cookie('session', 'abc123', { httpOnly: true });
```

### **Test 2: Missing Secure Flag**

**Objective**: Ensure cookies are only sent over HTTPS.

**Steps**:
1. **Capture Cookie**:
   - Log in and note the session cookie.
2. **Test HTTP Request**:
   - Use cURL:
     ```bash
     curl -i -b "session=abc123" http://example.com/dashboard
     ```
3. **Analyze Response**:
   - Check if cookie is sent and dashboard is accessible.
   - Expected secure response: HTTP 401 or redirect to HTTPS.
4. **Save Results**:
   - Save cURL output.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Dashboard Content
```

**Remediation**:
```python
response.set_cookie('session', 'abc123', secure=True)
```

### **Test 3: Weak SameSite Configuration**

**Objective**: Verify `SameSite` mitigates cross-site attacks.

**Steps**:
1. **Capture Cookie**:
   - Use Postman to log in and note `Set-Cookie`.
   - Command:
     ```
     New Request -> POST http://example.com/login -> Body -> JSON: {"username": "test", "password": "Secure123"} -> Send
     ```
2. **Test Cross-Site POST**:
   - Command:
     ```
     New Request -> POST http://example.com/update-profile -> Body -> JSON: {"name": "test"} -> Headers: Cookie: session=abc123 -> Send
     ```
3. **Analyze Response**:
   - Check if profile is updated.
   - Expected secure response: HTTP 401 if `SameSite=Strict`.
4. **Save Results**:
   - Save Postman outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
{"status": "Profile updated"}
```

**Remediation**:
```javascript
res.cookie('session', 'abc123', { sameSite: 'strict' });
```

### **Test 4: No Expiration Time**

**Objective**: Check if cookies have reasonable expiration settings.

**Steps**:
1. **Analyze Cookie**:
   - Use Python script to check `Expires` or `Max-Age`.
   - Command:
     ```bash
     python3 test_cookie_attributes.py
     ```
2. **Verify Duration**:
   - Check if `Max-Age` is absent or excessively long (e.g., years).
   - Expected secure response: `Max-Age=1800` (30 minutes).
3. **Save Results**:
   - Save script output.

**Example Vulnerable Output**:
```
Expires/Max-Age: Not Set
```

**Remediation**:
```python
response.set_cookie('session', 'abc123', max_age=1800)
```

## **Additional Tips**

- **Test All Cookies**: Check all session-related cookies, not just the primary session cookie.
- **Combine Tools**: Use Burp Suite for interception, Browser Developer Tools for client-side tests, and Python for automation.
- **Gray-Box Testing**: If documentation is available, verify cookie attribute requirements.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for testing, as cookie manipulation may disrupt user sessions or trigger security alerts.
- **References**: [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/).