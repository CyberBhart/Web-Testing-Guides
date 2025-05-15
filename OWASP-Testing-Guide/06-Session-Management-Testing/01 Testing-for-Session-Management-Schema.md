# **Testing for Session Management Schema**

## **Overview**

Testing for Session Management Schema (WSTG-SESS-01) involves assessing a web application’s session management mechanisms to ensure that sessions are securely created, maintained, and terminated, preventing vulnerabilities like session hijacking, fixation, or prediction. According to OWASP, weak session management can allow attackers to steal or manipulate session identifiers, gaining unauthorized access to user accounts. This test focuses on analyzing session identifier generation, cookie attributes, session lifecycle, and transmission to identify and mitigate risks in the session management schema.

**Impact**: Weak session management can lead to:
- Session hijacking by stealing or predicting session identifiers.
- Session fixation, where attackers force users to use known session IDs.
- Unauthorized access due to improper session termination or insecure attributes.
- Information disclosure through session IDs in URLs or unencrypted channels.

This guide provides a practical, hands-on methodology for testing the session management schema, adhering to OWASP’s WSTG-SESS-01, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing the session management schema, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts and analyzes session cookies and requests for secure attributes and fixation.
- **Postman**: Tests API endpoints for session handling and regeneration.
- **cURL**: Sends requests to inspect session IDs and lifecycle behavior.
- **Browser Developer Tools**: Inspects cookies, headers, and client-side session handling.
- **Python Requests Library**: Automates session ID collection and analysis for randomness.

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

This methodology follows OWASP’s black-box approach for WSTG-SESS-01, focusing on testing session identifier generation, cookie attributes, session lifecycle, fixation, and transmission.

### **1. Analyze Session Cookie Attributes with Burp Suite**

Inspect session cookies for secure attributes and proper configuration.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Login Request**:
   - Log in to the application and check “HTTP History” for the `Set-Cookie` header in the response.
   - Note the session cookie (e.g., `session=abc123`).
3. **Inspect Attributes**:
   - Check for `HttpOnly`, `Secure`, and `SameSite` attributes.
   - Verify cookie expiration (e.g., `Expires` or `Max-Age`).
   - Ensure the cookie is not accessible via JavaScript or transmitted over HTTP.
4. **Analyze Findings**:
   - Missing attributes (e.g., no `HttpOnly`) indicate vulnerabilities.
   - Expected secure response: All attributes set (e.g., `HttpOnly; Secure; SameSite=Strict`).
5. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Inspect session cookie:
  ```
  HTTP History -> Select POST /login -> Response tab -> Find Set-Cookie: session=abc123; Path=/ -> Check for HttpOnly, Secure, SameSite
  ```
- **Command 2**: Test cookie over HTTP:
  ```
  HTTP History -> Select GET /dashboard -> Send to Repeater -> Change https:// to http:// -> Click Send -> Check if cookie is sent
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
          maxAge: 3600000 // 1 hour
      }
  }));
  ```

### **2. Test Session Fixation with Postman**

Verify that the application regenerates session IDs upon authentication to prevent fixation.

**Steps**:
1. **Identify Login Endpoint**:
   - Use Burp Suite to find `POST /login`.
   - Import into Postman.
2. **Test Pre-Authentication Session**:
   - Send an unauthenticated request to get a session ID (e.g., `GET /`).
   - Log in using the same session ID and check if it changes.
3. **Analyze Responses**:
   - Compare session IDs before and after login.
   - Expected secure response: New session ID after login.
   - Vulnerable response: Same session ID persists.
4. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Get pre-authentication session:
  ```
  New Request -> GET http://example.com/ -> Headers: Cookie: session=abc123 -> Send -> Note Set-Cookie
  ```
- **Command 2**: Test login with same session:
  ```
  New Request -> POST http://example.com/login -> Body -> JSON: {"username": "test", "password": "Secure123"} -> Headers: Cookie: session=abc123 -> Send -> Check Set-Cookie
  ```

**Example Vulnerable Response**:
```
[Pre-login]
Set-Cookie: session=abc123

[Post-login]
Set-Cookie: session=abc123
```

**Remediation**:
- Regenerate session ID on login:
  ```python
  from flask import Flask, session
  app = Flask(__name__)
  @app.post('/login')
  def login():
      # Authenticate user
      session.regenerate() # Generate new session ID
      return jsonify({'status': 'success'})
  ```

### **3. Test Session Invalidation with cURL**

Check if sessions are invalidated server-side after logout or timeout.

**Steps**:
1. **Log In and Capture Session**:
   - Log in and note the session ID from the `Set-Cookie` header.
2. **Test Logout**:
   - Send a logout request (e.g., `POST /logout`).
   - Reuse the old session ID to access a protected resource (e.g., `/dashboard`).
3. **Test Timeout**:
   - Wait for the session timeout period (e.g., 30 minutes) and try reusing the session ID.
4. **Analyze Responses**:
   - Check if the old session ID grants access (HTTP 200).
   - Expected secure response: HTTP 401 or 403 after logout/timeout.
5. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Test session after logout:
  ```bash
  curl -i -b "session=abc123" http://example.com/dashboard
  ```
- **Command 2**: Test session after timeout:
  ```bash
  curl -i -b "session=abc123" http://example.com/dashboard
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
Dashboard Content
```

**Remediation**:
- Invalidate sessions on logout:
  ```javascript
  app.post('/logout', (req, res) => {
      req.session.destroy();
      res.clearCookie('session');
      res.json({ status: 'success' });
  });
  ```

### **4. Inspect Session Transmission with Browser Developer Tools**

Analyze how session IDs are transmitted to detect insecure practices.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Inspect Requests**:
   - Check “Network” tab for session IDs in URLs (e.g., `?session=abc123`) or HTTP headers.
   - Verify if requests use HTTPS (lock icon in browser).
3. **Test Insecure Transmission**:
   - Force an HTTP request (e.g., edit URL to `http://`) and check if the session cookie is sent.
   - Expected secure response: Cookie not sent over HTTP.
4. **Document Findings**:
   - Save screenshots and network logs.

**Browser Developer Tools Commands**:
- **Command 1**: Check for session in URL:
  ```
  Network tab -> Select GET /dashboard -> Request URL -> Look for ?session=abc123
  ```
- **Command 2**: Test HTTP transmission:
  ```
  Network tab -> Edit GET https://example.com/dashboard to http://example.com/dashboard -> Reload -> Check if Cookie header includes session
  ```

**Example Vulnerable Request**:
```
GET /dashboard?session=abc123 HTTP/1.1
```

**Remediation**:
- Avoid session IDs in URLs:
  ```python
  @app.route('/dashboard')
  def dashboard():
      if not request.cookies.get('session'):
          return jsonify({'error': 'Unauthorized'}), 401
      return jsonify({'data': 'Dashboard'})
  ```

### **5. Analyze Session ID Randomness with Python Requests**

Collect and analyze session IDs to ensure they are unpredictable.

**Steps**:
1. **Write Python Script**:
   - Create a script to collect multiple session IDs:
     ```python
     import requests
     import base64
     import re

     url = 'http://example.com/login'
     session_ids = []
     for i in range(5):
         response = requests.get(url)
         session_id = response.cookies.get('session')
         if session_id:
             session_ids.append(session_id)
             print(f"Session ID {i+1}: {session_id}")
         # Check for patterns (e.g., incremental, timestamp)
         if len(session_ids) > 1:
             if any(s in session_ids[0] for s in session_ids[1:]):
                 print("Potential predictability detected")
     # Basic randomness check
     for sid in session_ids:
         try:
             decoded = base64.b64decode(sid).hex()
             print(f"Decoded {sid}: {decoded[:20]}...")
         except:
             print(f"{sid} not base64-encoded")
     ```
2. **Run Script**:
   - Execute: `python3 test_session_ids.py`.
   - Analyze session IDs for patterns, length, or encoding.
3. **Verify Findings**:
   - Check if IDs are short, incremental, or timestamp-based.
   - Expected secure response: Long, random IDs with no patterns.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run session ID test:
  ```bash
  python3 test_session_ids.py
  ```
- **Command 2**: Test single session ID:
  ```bash
  python3 -c "import requests; r=requests.get('http://example.com/'); print(r.cookies.get('session'))"
  ```

**Example Vulnerable Output**:
```
Session ID 1: user1_123456
Session ID 2: user2_123457
Potential predictability detected
```

**Remediation**:
- Use cryptographically secure session IDs:
  ```python
  import secrets
  @app.route('/login')
  def login():
      session_id = secrets.token_urlsafe(32)
      response.set_cookie('session', session_id, httponly=True, secure=True, samesite='Strict')
      return response
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-SESS-01 with practical scenarios based on common session management vulnerabilities observed in penetration testing.

### **Test 1: Insecure Cookie Attributes**

**Objective**: Verify if session cookies have secure attributes.

**Steps**:
1. **Capture Cookie**:
   - Use Burp Suite to intercept `POST /login`.
   - Command:
     ```
     HTTP History -> Select POST /login -> Response tab -> Find Set-Cookie: session=abc123
     ```
2. **Analyze Attributes**:
   - Check for `HttpOnly`, `Secure`, `SameSite`.
   - Command:
     ```
     HTTP History -> Select POST /login -> Response tab -> Note missing attributes
     ```
3. **Test Insecure Access**:
   - Access cookie via JavaScript in Browser Developer Tools:
     ```
     Console tab -> Run: document.cookie -> Check if session=abc123 is accessible
     ```
4. **Save Results**:
   - Save Burp Suite and screenshots.

**Example Vulnerable Response**:
```
Set-Cookie: session=abc123; Path=/
```

**Remediation**:
```javascript
res.cookie('session', 'abc123', {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
});
```

### **Test 2: Session Fixation**

**Objective**: Test if session IDs are regenerated after login.

**Steps**:
1. **Get Pre-Login Session**:
   - Use Postman to send `GET /`.
   - Command:
     ```
     New Request -> GET http://example.com/ -> Send -> Note Cookie: session=abc123
     ```
2. **Log In**:
   - Command:
     ```
     New Request -> POST http://example.com/login -> Body -> JSON: {"username": "test", "password": "Secure123"} -> Headers: Cookie: session=abc123 -> Send -> Check Set-Cookie
     ```
3. **Analyze Response**:
   - Check if session ID changes.
   - Expected secure response: New session ID.
4. **Save Results**:
   - Save Postman outputs.

**Example Vulnerable Response**:
```
Set-Cookie: session=abc123
```

**Remediation**:
```javascript
app.post('/login', (req, res) => {
    req.session.regenerate(() => {
        // Set new session ID
        res.json({ status: 'success' });
    });
});
```

### **Test 3: Session Invalidation**

**Objective**: Verify that sessions are invalidated after logout.

**Steps**:
1. **Log In**:
   - Use cURL to log in and capture session ID.
   - Command:
     ```bash
     curl -i -X POST -d "username=test&password=Secure123" http://example.com/login
     ```
2. **Log Out and Test**:
   - Command:
     ```bash
     curl -i -b "session=abc123" http://example.com/dashboard
     ```
3. **Analyze Response**:
   - Check if dashboard access is granted.
   - Expected secure response: HTTP 401.
4. **Save Results**:
   - Save cURL outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Dashboard Content
```

**Remediation**:
```python
@app.post('/logout')
def logout():
    session.clear()
    response = jsonify({'status': 'success'})
    response.set_cookie('session', '', expires=0)
    return response
```

### **Test 4: Session ID in URL**

**Objective**: Detect session IDs transmitted in URLs.

**Steps**:
1. **Inspect Requests**:
   - Use Browser Developer Tools to check URLs.
   - Command:
     ```
     Network tab -> Select GET /dashboard -> Check for ?session=abc123 in Request URL
     ```
2. **Analyze Response**:
   - Confirm session ID presence in URL.
   - Expected secure response: Session ID only in cookies.
3. **Save Results**:
   - Save screenshots.

**Example Vulnerable Request**:
```
GET /dashboard?session=abc123
```

**Remediation**:
```javascript
app.get('/dashboard', (req, res) => {
    if (!req.cookies.session) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    res.send('Dashboard');
});
```

## **Additional Tips**

- **Test Multiple Scenarios**: Analyze session behavior across browsers, devices, and authentication states.
- **Combine Tools**: Use Burp Suite for manual testing, Postman for APIs, and Python for automation.
- **Gray-Box Testing**: If documentation is available, verify session ID generation algorithms or timeout policies.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for testing, as session manipulation may disrupt user sessions or trigger security alerts.
- **References**: [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/).